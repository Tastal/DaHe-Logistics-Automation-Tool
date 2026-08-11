# ADR-062: Streaming progress and cooperative abort

## Context

Network batches are useful durable recovery boundaries, but reporting progress and checking cancellation only once per batch makes a 50-item read appear frozen and delays cancellation until the entire batch finishes.

## Decision

The browser protocol separates transient control events from durable checkpoints. The worker streams page, detail and image progress without creating database transactions. Durable evidence is still committed only at the job's frozen network batch boundary.

While a read is active, the worker accepts an `abort` control message, stops scheduling new detail and image reads, cancels the controlled page, discards the uncommitted batch and emits `abort_ack`. If no acknowledgement arrives within two seconds, the supervisor may terminate only the worker registered to the current DaHe instance.

Transient progress is never used as recovery evidence. Restart recovery resumes from the latest committed batch.

## Consequences

- The UI can update item by item without reducing database throughput.
- Cancellation becomes responsive while preserving committed evidence.
- A crash can still redo at most the current uncommitted batch.
- The browser protocol is more complex, so framing, ordering and redaction require explicit tests.
