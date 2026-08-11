# ADR-046: Two-page Historical Locked-set Pool

## Context

The first current-build historical capture completed 100 details and 200
ticket images with zero denied, redirected, or platform-write requests. The
existing full-history identity, exact-image, perceptual-similarity, and
development exclusions left only 42 eligible waybills. The one-page limit in
ADR-036 therefore could not produce the required 50-waybill locked set.

Relaxing perceptual similarity or development exclusions would weaken the
unseen-data gate. Traversing history until enough items happen to remain would
make the platform read unbounded and the candidate population difficult to
replay.

## Decision

The `settled_history` candidate source keeps the official reset ordering and a
fixed page size of 100. It reads one page when the declared platform total is
at most 100 and exactly the first two pages when the total is greater than
100. The source is capped at two pages and 200 captured waybills even when the
platform declares a larger total.

Both pages must use the same build, selected contract, identity context, job,
and bounded access-window lineage. Page numbers must be contiguous from one,
and each captured page must contain the exact bounded item count implied by
the declared total. A third page, a gap, an inconsistent total, or an
incomplete bounded page fails closed.

Formal selection continues to apply the same HMAC ranking and full-history
identity, exact-image, perceptual-similarity, and development exclusions. If
the first 200 recent candidates still cannot provide 50 eligible waybills,
the generation fails. The implementation must not continue paging or lower an
exclusion threshold.

The completed 100-waybill capture that exposed the shortfall is registered as
development evidence with all 100 protected platform identities, 200 image
hashes, 200 perceptual fingerprints, and its scope token. It cannot be reused
by the new build as formal evidence. The code change requires a new build
fingerprint and a new formal capture.

This decision supersedes only ADR-036's one-page historical limit. It does not
change the source separation, request contract, 30-waybill current-shadow
requirement, or any Loop 9 acceptance threshold.

## Consequences

- The source remains deterministic and bounded while providing a larger
  candidate pool for heavily overlapping company ticket layouts.
- Platform exposure can increase from 301 successful reads for 100 waybills
  to at most 602 successful reads for 200 waybills, assuming two images per
  waybill and two list requests.
- Similar images remain excluded instead of being accepted to satisfy the
  sample count.
- Existing failed evidence remains replayable as development history, but all
  formal locked-set evidence must be regenerated from the new build.
- A later need for more than 200 historical candidates requires a separate
  measured decision rather than an automatic retry loop.
