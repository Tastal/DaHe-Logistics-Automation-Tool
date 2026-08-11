# ADR-066: Reconcile the Exact Daily Response Scope

## Context

The Chengfeng `/wayBill` screen can continue to display the unfiltered account-wide total while the isolated browser worker substitutes the approved 14:00-to-14:30 business fields into the page-owned query. A real read on 2026-08-10 returned an exact-scope response total of zero while the visible unfiltered page still showed 25,378 records. Treating those two totals as the same scope made a valid empty read fail after the fresh response had already passed its request and response contracts.

## Decision

The exact page-owned request and its newly observed response are the daily scope authority. Completeness requires a validated scope hash, response total, response page count, complete pagination, unique identities, and an unchanged final candidate set. The visible page total is retained only when it equals the response for the same controlled scope. Otherwise it is recorded as unavailable rather than compared across scopes.

The browser worker must still navigate the single visible Chengfeng tab to `/wayBill`, disable cache, reload with `ignoreCache=true`, observe a new native query response, validate the controlled request body, and reject platform writes. This decision does not permit stale responses, cached snapshots, a broader local fallback, or a second local time filter.

## Consequences

- A real zero-result business window can complete without being compared to an unrelated account-wide page total.
- Response pagination, identity reconciliation, and final candidate reconciliation remain fail-closed.
- A comparable page total still must match; an unproven display total is nullable evidence, not authority.
- Raw requests, responses, cookies, and platform values remain browser-worker private.
