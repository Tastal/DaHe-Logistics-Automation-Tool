# ADR-069: Atomic whole-run capture and contiguous offline review

## Status

Accepted. This decision supersedes ADR-057 and ADR-062 only for new operational Chengfeng business reads. Historical `batch_v1` jobs remain readable and recoverable under their original contracts.

## Decision

New settlement and daily reads use `whole_run_v1`.

- Platform pagination enumerates and freezes the complete authoritative identity set. It is not a durable business batch boundary.
- Details are read with bounded concurrency 4 and images with bounded concurrency 6. The Worker stages each downloaded payload immediately and returns only relative paths, byte counts, media types, and SHA-256 values.
- The application publishes no partial online result. It first reconciles list totals, unique identities, detail identities, staged files, hashes, and the zero-write request audit, then commits one online result.
- One source capture creates at most one offline review Job. The one-to-one link is append-only and idempotent.
- The operator workspace remains non-terminal while offline review is active. It displays only the contiguous completed prefix in frozen waybill order, so parallel completion cannot reorder visible records.
- A current daily observation whose fields match the latest append-only machine revision inherits that revision in the read projection. Field deduplication does not create a duplicate revision and does not remove the waybill from the current whole-run workspace.
- Online capture permits cancellation but not pause. Offline review permits pause and resume and retains completed work items.
- A missing platform ticket image is valid business data for manual review. A transport, contract, incomplete response, or staging failure fails the entire unpublished online run.
- If the owned browser Worker fails during initial startup, the same business task may rebuild it once. Login intervention keeps the same task waiting and continues after login.

## Consequences

The operator no longer sees a partial count such as 71 as the final result of a 97-waybill capture. There are no inter-batch delays or repeated OCR child-job setup costs for new tasks. A failed online run may repeat more network work on the next manual start, which is accepted in exchange for simpler and faster business behavior. SQLite remains free of long browser and OCR transactions because files are staged outside the commit gate and the atomic publication transaction contains metadata only.
