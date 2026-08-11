# ADR-028: Worker-Private Chengfeng List Baseline

## Context

The frozen Chengfeng list contract proves field names and types, but it does
not retain production request values. The official page owns three fixed list
controls, `order`, `queryType`, and `settleQueryType`. Guessing any value in the main
application can produce a structurally valid authenticated response with an
incorrect empty business scope.

Retaining the full official request body would also retain user-entered
filters and would expand credential and production-data exposure beyond the
Loop 9 contract.

## Decision

After browser control is returned, the isolated Worker installs an abort-all
route, selects Waybill View, resets all filters, and clicks Query. No request
from this normalization sequence may reach Chengfeng.

From the exact approved list request, the Worker may keep a bounded reset
baseline only when every value satisfies one of these rules:

- `order`, when it is `asc` or `desc`;
- `queryType`, when it is empty or one ASCII digit;
- `settleQueryType`, when it is an approved small integer;
- other string fields, only when empty or a single ASCII digit;
- list fields, only when empty;
- page number and page size, only when positive integers;
- the single `t` query value, when its value is 10 to 20 ASCII digits.

Any longer non-empty string, non-empty list, nested value, Boolean, or
unbounded number rejects the baseline before network access. The main process continues to
authorize the complete frozen parameter shape and owns page number and page
size. Immediately before the formal list request, the Worker requires the
same field set, rejects non-empty application filters, uses its reset baseline,
replaces only page number and page size, and appends the
private `t` cache query. The query is permitted only on the exact list request
and is never attached to detail or image reads.

The Worker also computes a canonical SHA-256 of the locally constructed body
after replacing only page number and page size with neutral placeholders.
Before network access it computes the same hash from the final formal body.
Any difference fails closed. Only the hash is retained; the reset body and
its field values are not retained or exported.

The values never cross NDJSON, never enter logs, databases, diagnostics,
evidence, or exports, and are cleared with the browser context. Missing,
invalid, or changed values fail closed before the formal read.

## Consequences

Formal reads use the page's current list semantics without making those
production values part of the durable contract. The extra reset-and-query
step is local and network-blocked, so it cannot consume an unrecorded platform
read. Tests must prove reset ordering, abort-all routing, strict value bounds,
protocol non-disclosure, bounded reset values, list-only cache query use,
exact normalized-body equality, and close-time clearing.
