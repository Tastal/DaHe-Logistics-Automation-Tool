# ADR-036: Bounded Locked-Set Sources

ADR-046 supersedes only this decision's original one-page historical limit.
The source separation, request contract, and formal gate boundaries below
remain in force.

## Context

The current pending-settlement list can contain fewer than the 50 waybills
required by the new Loop 9 OCR locked set. Waiting for 50 simultaneously
pending waybills would couple an OCR safety gate to the company's settlement
timing. Reusing legacy images or earlier discovery samples would violate the
unseen-data and development-exclusion rules.

Historical settled waybills contain the same loading and unloading ticket
evidence needed by the OCR and role-safety gate. They are not valid substitutes
for the 30-waybill production-shadow batch, whose purpose is to exercise the
current pending-settlement workflow.

## Decision

The 50-waybill locked set first uses `current_pending` when the final
exclusion pass leaves at least 80 eligible waybills. The stable selection takes
50 and reserves at least 30 non-overlapping candidates for the later
production-shadow batch. If this reserve gate cannot be met, the locked set
may use the distinct `settled_history` source. The 30-waybill
production-shadow batch always uses `current_pending`.

The two sources share only the selected detail and response-derived image
operations. Their list reads are deliberately distinct:

- `current_pending` uses the selected pending-settlement list declaration.
- `settled_history` uses the exact `/rejectedReturnBill` page and the exact
  `queryClientAllFinishSettlementOrderItemListPC` POST endpoint.

The historical list contract is a deterministic, build-bound supplement to the
selected read-only contract. It accepts only `deptCode`, `pageNumber`,
`pageSize`, and an empty `sortParams` array. The browser worker obtains the
non-empty department value and the single bounded cache query directly from
the official page, retains them only in worker memory, and replaces the main
process placeholders before sending. Its response decoder requires
`orderItemId`, `orderItemSn`, `carNumber`, and a canonical digit-string
`total`; it does not reuse the pending decoder or infer omitted pagination
fields.

The historical page is opened before the deny-by-default request route is
installed. Once the page controls are available, the worker arms the route,
executes exactly one native query probe, aborts unrelated requests, and closes
the human page before automated reads. The main process does not receive,
persist, guess, or copy the department value, cache query, credentials, or raw
probe response.

Current collection remains paginated by the frozen 50-item request contract
and is sealed before selection. Historical collection uses the deterministic
bounded recent-candidate window defined by ADR-046 under the official reset
ordering. It does not traverse the complete settlement history. Formal
selection then applies the existing
installation-local identity, HMAC rank, exact-image exclusion, perceptual
similarity exclusion, and development-history exclusion rules to select exactly
50 unique waybills. Fewer than 50 eligible results fail closed.

Every capture manifest, checkpoint, request audit, formal selection, dataset
artifact, and replay records and validates the source kind. A historical
capture cannot produce the real-shadow 30, and a pending capture cannot be
silently relabeled as the historical locked set.

## Consequences

- When enough current candidates exist, the locked set and later shadow batch
  can use the same business population while remaining identity- and
  image-disjoint.
- OCR acceptance does not depend on 50 waybills remaining simultaneously
  unsettled because the historical fallback remains available.
- The platform read remains bounded and does not crawl unbounded company
  history.
- Historical waybills are still new evidence only when this build first reads
  them and all full-history exclusions pass.
- A pending-list response cannot be decoded as historical data, and a
  historical-list response cannot be decoded as a pending result.
- The locked-set gate and production-shadow gate keep distinct business
  meanings even though they reuse the same response structure contract.
- Any change to source controls, contract shape, build, exclusion authority, or
  OCR implementation invalidates the affected formal generation.
