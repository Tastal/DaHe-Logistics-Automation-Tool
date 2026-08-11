# ADR-034: Exact Image Capability and Request Audit

## Context

Chengfeng detail responses contain dynamic signed ticket-image addresses. A
host allowlist alone would authorize unrelated paths on the same CDN. Final
Loop 9 acceptance also needs measured request evidence; static expected counts
or a hard-coded zero cannot prove that no denied, redirected, or write request
occurred.

## Decision

The browser runtime grants a five-minute in-memory capability only for each
complete image address returned by a successfully validated waybill-detail
response. The capability is bound to that exact response-derived address.
Unseen addresses, changed signatures, alternate paths, encoded bypasses,
expired capabilities, and redirects are rejected before network access. The
complete address is never persisted or returned in diagnostics.

The durable checkpoint stores only the opaque ticket reference plus hashes of
the connector/browser capability generation and its access-window identity.
It does not store the address or a reusable capability. If the main process,
browser worker, or short-lived grant is no longer current while an image is
missing, the coordinator reads that waybill detail again from its safe
checkpoint. It validates that all business evidence is unchanged, maps the
replacement references only by the explicit `loading` and `unloading` slots,
keeps references for already committed images, and downloads only missing
images. A refreshed detail must issue new opaque references; a stale reference
is never retried after browser recovery.

Every formal platform-read Job uses an append-only request audit. Each
operation records the bounded phases `attempted`, `allowed`, and one terminal
phase: `succeeded`, `denied`, `failed`, or `redirect`. Audit records contain
only operation identities, authority hashes, safe counts, and an event-chain
hash; they contain no URL, response body, OCR text, credential, or platform
identifier.

Contract binding is operation-specific. Settlement list, detail, and image
reads bind the selected settlement contract. A daily list read binds the
selected daily contract, while any shared detail and image reads still bind
the selected settlement contract. The 50-item and 30-item formal batches cannot
carry a daily-list authority.

The audit store uses process and Windows file locking, rejects concurrent
sealing with an in-flight request, and publishes a content-addressed immutable
seal only after deep event-chain replay. Expected successful operations are
derived from committed source records. The 50-item batch, 30-item batch, and
each of the three daily snapshots bind their own sealed audit evidence
directly; the final command cannot substitute those identities.

Each successful capability refresh is another attributable detail operation
in the same Job audit. Its access-window binding is append-only, so formal
operation counts include the refresh without pretending that a previously
committed image was downloaded again.

## Consequences

- Knowing an approved CDN host does not authorize an arbitrary image request.
- Retries and failures remain visible without exposing signed addresses or
  response contents.
- Restart recovery cannot reuse an expired signed address or remap a ticket by
  weight, OCR output, or upload order.
- Deleted, reordered, duplicated, cross-authority, or post-seal events fail
  replay.
- Final `shadow_accepted` requires five upstream request-audit seals with zero
  denied, redirected, and platform-write requests.
