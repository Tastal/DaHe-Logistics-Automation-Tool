# ADR-068: Daily workspace and console convergence

## Context

The operational daily backend already stores records by business date, but the
frontend could retain the previous date while another request was in flight and
could accept responses out of order. Manual save reported success before the
backend proved that every current issue was resolved. Daily browser preparation
also passed through the settlement page even though the two businesses have
different list contracts. The operator system view exposed scheduler and local
resource detail that was useful to development but not to finance users.

## Decision

The selected business date and a monotonically increasing frontend request
generation jointly authorize a daily response. Changing the date synchronously
clears items and counts. A response, save result or error from an older
generation cannot change the selected date view.

Saving a daily item is an explicit confirmation of all current issue fields.
The request binds the business date and record version and includes every
unresolved field; `null` is a deliberate manual blank. The backend returns the
latest item and authoritative counts. Only a returned `reviewed` state can
produce the completed toast.

The browser protocol has a dedicated `prepare_operational_daily` command. It
uses the shared visible-Edge, single-tab, foreground, login, cache-disabled
reload, fresh-response and read-only-audit primitives, but navigates directly to
`/wayBill`. It does not prepare or query `/billablewaybill`. Settlement and
daily list contracts, query fields, snapshots, conflict keys and integrity
checks remain separate.

One backend projection supplies the sidebar connection label. Its fixed states
are browser closed, opening, login required, ready, reading, downloading and
error. The frontend polls only while visible and refreshes immediately on
focus; it does not infer platform state from buttons or old jobs.

The operator system view defaults to diagnostics and retains only diagnostics,
templates and settings. Scheduler jobs, local resources, data management and
the recent-issues list remain available to backend or diagnostic contracts
where required but are not rendered. The four bottom utilities are icon-only,
keyboard accessible and use portal tooltips. Six diagnostic/log operations
share one responsive action row.

## Consequences

- One business date cannot display another date's records or counts.
- Manual blanks are durable review decisions without a new database migration.
- Daily reads avoid settlement preparation latency while preserving the common
  browser safety pipeline and the platform-write prohibition.
- Finance users see one concise connection state and one focused diagnostics
  surface; technical scheduling detail remains outside the operator interface.
