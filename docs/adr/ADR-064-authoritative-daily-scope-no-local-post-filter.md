# ADR-064: Preserve the Authoritative Daily Identity Set

## Context

The Chengfeng daily page can return a bounded safety tail through 14:30 on the next day. The browser worker reconciles the page display total, response total, pagination, and unique identities before returning the candidate list. A second application-layer filter previously removed candidates whose loading time fell outside a stricter 14:00-to-14:00 interval. This produced a snapshot that claimed 68 reconciled identities while only 62 candidates reached local processing.

## Decision

The identity set reconciled by the Chengfeng page and browser worker is authoritative for the selected daily scope. The application freezes every returned identity and does not apply another loading-time or ticket-time filter. The final candidate count must equal the reconciled unique identity count. A mismatch fails closed with an incomplete-scope diagnostic and cannot be stored as a successful snapshot.

The 14:30 safety tail remains part of the current read-only query contract. Historical 13:30-start snapshots remain readable but cannot create new production reads.

## Consequences

- Boundary candidates are no longer silently lost after platform reconciliation.
- Completeness evidence now covers the final local candidate count as well as platform and response totals.
- Business reports may include candidates returned by the approved safety-tail query; any future narrowing must be made explicit in the platform query contract rather than as a hidden local post-filter.
- Requests, cookies, signed URLs, and raw responses remain private to the browser worker.
