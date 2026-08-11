# ADR-045: Interleaved Formal Ticket Image Capture

## Context

The strict Loop 9 settlement capture originally completed every detail on a
100-waybill page before downloading any ticket image. Each detail creates
image capabilities that live for only five minutes. A real historical capture
needed longer than that to read all 100 details, so the earliest capabilities
expired before the image phase. Refreshing every expired detail could repeat
indefinitely without committing an image.

## Decision

New strict captures process each waybill as an ordered sequence: read its
detail, download and commit every referenced ticket image, then advance to the
next waybill. Each detail and image remains a separately authorized atomic
read with its own durable checkpoint and access-window lineage.

The legacy page-wide order remains the default behavior of the reusable
coordinator for read-only compatibility. The current application explicitly
enables interleaving. Existing checkpoints that already contain multiple
details resume by completing the earliest missing images before reading more
details, without rewriting committed evidence.

## Consequences

- A short-lived image capability is normally consumed immediately instead of
  expiring behind a long detail phase.
- Pause, cancellation, restart, and fair resource rotation still occur between
  atomic platform reads.
- Already committed images are never downloaded again during normal recovery.
- The ordering change alters the current build fingerprint, so all build-bound
  Loop 9 formal evidence must be regenerated before acceptance.
