# ADR-027: Chengfeng Pagination Metadata Normalization

## Context

Authorized read-only validation proved that Chengfeng uses more than one
pagination representation. An empty first page can return zero for both
`pageNo` and `pageSize`. A non-empty pending-settlement page can return the
number of rows in `pageNo` and the requested page number in `pageSize`, while
the approved request and DaHe's scheduler use one-based page number plus page
capacity. Treating those response names as standard pagination fields rejected
a real non-empty list before any detail or image request.

## Decision

Treat Chengfeng's response page number as a representation detail. Accept it
when it equals the requested one-based page number, exactly one less, or when
the response provides the exact paired representation of `pageNo == returned
row count` and `pageSize == requested page number`. Normalize the resulting
`WaybillPage` to the requested one-based number.

Treat a zero response page size only as an unfilled metadata placeholder and
replace it with the already approved request size. For the paired
representation, also normalize page size to the approved request size. Every
other nonzero response size must equal the request size. Total must be
non-negative, returned item count must fit the normalized page size and total,
and any other page-number relationship fails closed.

## Consequences

The connector supports the observed placeholder, paired, zero-based and
one-based representations without exposing platform-specific pagination to
the scheduler. The paired representation is accepted only when both fields
agree with the returned row count and the requested page number. Full capture
still reconciles total count, page count and unique identities, so repeated or
skipped pages fail closed. The failed validation window remains failed; a fresh
authorized validation is required.

The fixed operational page must finish rendering before login control is
returned. The browser then reuses that page under a narrow route and performs
the fixed pending-settlement, settlement, waybill-view, reset, waybill-view
and query controls. It waits for each SPA redraw and reacquires the controls.
Transition list reads may finish but only the final query response becomes
authority. It does not reload the SPA or replay application bootstrap traffic.
A later read after a business `human_handoff` still requires a new controlled
context and a new snapshot because manual platform work may have changed the
page state. The rebuilt context must render the fixed entry controls before
the narrow query route is installed; installing it immediately after main
document commit would block the remaining SPA bootstrap and create a false
control-unavailable failure.

A first authoritative zero is not accepted immediately. The worker removes
the query route, clears only the isolated DaHe browser HTTP cache, temporarily
disables that cache, reloads the fixed entry while preserving cookies and site
storage, restores the narrow route and repeats the same page-owned query. Only
a second zero is treated as an empty business list. This fallback is bounded
to the zero case because a stale cached frontend was observed to return zero
while the cache-bypassed page returned the current non-zero list.
