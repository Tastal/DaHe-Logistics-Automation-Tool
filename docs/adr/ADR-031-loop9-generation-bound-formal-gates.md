# ADR-031: Generation-bound Loop 9 Formal Gates

## Context

Loop 9 uses a current 50-waybill locked set before it may collect the
30-waybill real shadow set. A content-addressed batch alone does not prove that
it is the installation's active formal selection, that its natural-image
coverage remains eligible, or that the current build passed the locked-set
machine gate.

Natural coverage can also fail after all 50 waybills have been reviewed. The
review work must remain useful as development evidence, but the failed
selection must never become current again or authorize a real shadow run.

## Decision

The current locked selection is an append-only generation lifecycle. Each
generation has one active or invalidated lifecycle tip bound to its selection,
build, OCR pipeline, identity context, exclusion authority, and exclusion
history head.

If natural coverage is incomplete, an offline idempotent command:

- binds the complete human review to the exact active selection;
- records an immutable coverage-failure attestation;
- registers every waybill and image in the development exclusions;
- advances the exclusion authority; and
- invalidates that selection generation.

A replacement may be activated only from the invalidated tip and the advanced
exclusion authority. Retrying the same invalidation is safe; an older
generation is never revived.

The current locked-set Gate is separate append-only evidence. Publishing it
requires the exact active locked generation, the current source build, the
active settlement contract, a complete sealed human review, and a deeply
replayed CPU/GPU machine result. The Gate cannot trust build or contract hashes
reported by the evidence being checked.

Every `real_shadow_30` selection binds the exact current Gate SHA-256 and its
locked generation. Job creation, browser execution, formal dataset creation,
human review, machine evaluation, and replay all revalidate the active
selection, current build, active settlement contract, and Gate. A batch file
without this chain is development data, not formal evidence.

## Consequences

- Natural coverage failure cannot be converted to a waiver or a successful
  Gate.
- Reviewing a failed generation does not require deleting its evidence, but
  all of its identities and images become permanent development exclusions.
- A build, contract, pipeline, exclusion authority, selection generation, or
  Gate change invalidates downstream formal evidence rather than being
  silently accepted.
- Formal evidence remains protected by local file permissions and complete
  hash replay. It is not a cryptographic signature against an attacker who
  already controls the entire data root.
