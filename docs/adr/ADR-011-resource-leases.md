# ADR-011: Resource Leases

## Context

Audit, reporting, and maintenance must make progress without a global busy lock.

## Decision

Coordinate work with per-resource leases, fair queues, conflict keys, dependencies, and persistent checkpoints.

## Consequences

Unrelated jobs can run concurrently. Scheduling, cancellation, recovery, and starvation prevention require explicit tests.
