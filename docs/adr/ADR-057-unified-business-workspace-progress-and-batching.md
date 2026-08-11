# ADR-057: Unified business workspace, timed progress, and frozen network batches

## Decision

Settlement and daily operations use one main scroll container and the same operation, progress, filter, and list layout. Business pages do not create nested viewport scroll containers.

Operational network batch size is frozen per Job. New Jobs accept 20, 50, or 100 items; existing 15-item Jobs remain recoverable. The production default is 50. An isolated read-only benchmark of 123 daily waybills selected it because its two-run median was about eight percent faster than 20, while both 100-item trials failed safely after the controlled browser closed. The smaller batch remains preferred whenever measured speed differs by less than five percent.

Progress projections include task and phase timestamps, elapsed time, and an estimate state. SSE events are emitted when phase or counters change. Estimates are shown only when enough completed work exists.

## Consequences

- Both business modules remain visually and behaviorally consistent.
- A setting change cannot alter an active or historical Job.
- Larger batches may improve throughput but increase the amount repeated after an uncommitted crash.
- The 100-item option remains available for diagnosis but is not recommended on the verified machine profile.
- Historical 15-item evidence is not rewritten.
