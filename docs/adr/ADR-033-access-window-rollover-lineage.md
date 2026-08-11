# ADR-033: Access Window Rollover Lineage

## Context

A real read-only capture can outlive its one-time access window. Requiring a
new capture would repeat already committed reads, while replacing the access
window identity in place would make it impossible to prove which authority
permitted each list, detail, and image read. A concurrent human-login start can
also race with a rollover unless both operations share the browser lifecycle
fence.

## Decision

An access window may be replaced only for the same paused, collecting Job and
browser session. The previous window must already be expired or consumed, the
browser must be idle, and the current build, settlement contract, daily
contract, identity authority, and capture digest must still match.

Human-login start and rollover both take the browser lifecycle lock and repeat
authorization checks inside that lock. Rollover consumes the old window and
advances the browser control epoch and record version in the same database
transaction. It never navigates, starts the browser, resumes the Job, or
reuses an old automation token.

Every completed list, detail, and image read records the access window that
actually authorized it. Checkpoints preserve those bindings, and capture
manifest schema version 2 publishes the ordered, append-only window lineage
plus per-read bindings. A resumed capture requests only missing reads. Existing
results without provenance cannot be adopted into a new formal capture.

If an access window expires during collection, the execution result pauses the
Job with its WorkItem in `waiting_external`; it is not a business review or a
terminal technical failure. Only the existing access-window rollover operation
may bind a replacement window. After rollover and explicit resume, a stale
image-reference generation causes a new detail read under the replacement
window, followed only by the still-missing image reads. Already committed
content-addressed evidence remains unchanged.

Idempotent rollover replay must revalidate the complete current authority
instead of returning a previously stored response solely from its key.
Historical single-window manifests remain readable under their original
schema, but they cannot be promoted into a multi-window formal capture without
the required provenance. The compatibility verifier may replay schema version
4 only for historical inspection. Every current Loop 9 dataset build,
operational evidence publication, and final acceptance replay requires schema
version 5 and revalidates both the ordered window lineage and every per-read
window binding.

Schema version 5 evidence is not its own formal authority. Operational and
final acceptance replay reload the selected daily contract and all three
`DailySnapshotCaptureAuthority` records from the formal data-root SQLite
database; loading each authority also replays its sealed request audit. The
same triplet builder then reconstructs the complete evidence, which must match
the submitted document field for field and by canonical SHA-256. An unused
window, reordered lineage prefix, or changed image identity or slot therefore
fails even when an altered document remains internally consistent and is
rehashed.

## Consequences

- A long capture can continue after a safe pause without rewriting earlier
  evidence or repeating completed image downloads.
- An expired window and every automation token fenced by its epoch are unusable
  after rollover.
- Formal replay can attribute each atomic platform read to one exact access
  window.
- Legacy checkpoints that contain committed reads but no source-window
  identity fail closed instead of receiving invented lineage.
