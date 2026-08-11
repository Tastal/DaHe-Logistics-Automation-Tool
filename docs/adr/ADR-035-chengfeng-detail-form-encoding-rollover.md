# ADR-035: Chengfeng Detail Form-Encoding Rollover

## Context

The selected Chengfeng read contract correctly froze the pending-settlement
list, detail response, and ticket-image shapes, but its first discovery record
classified every POST body as JSON. Read-only comparison with the legacy
adapter showed that the detail endpoint is submitted as
`application/x-www-form-urlencoded`. A live detail request using JSON returned
no usable item even though the same platform identity was valid.

Silently trying both encodings would widen the request contract, make request
audits ambiguous, and allow future platform changes to be mistaken for a
successful fallback.

## Decision

The list operation remains JSON encoded. The detail operation is form encoded.
The encoding location is part of the deny-by-default request contract and is
validated before any network request.

Historical JSON-classified evidence remains available for read-only replay but
cannot drive a live detail request. A dedicated, content-addressed rollover may
change only `get_waybill_detail.parameters_location` from `json` to `form`.
It must preserve and revalidate the parent selection, list contract, request
fields, response fields, detail identity rules, ticket-image capability, and
all source hashes. The rollover is atomic and idempotent.

## Consequences

- Live reads never guess an encoding or retry a detail request with another
  body format.
- Existing evidence is not rewritten, deleted, or falsely treated as the
  corrected authority.
- The selected rollover must pass a fresh real read validation under the
  current build before it can support any formal data capture.
- A future encoding or semantic change requires another explicit discovery and
  authority decision.
