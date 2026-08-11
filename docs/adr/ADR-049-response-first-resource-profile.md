# ADR-049: Response-first production resource profile

## Decision

Production defaults to a response-first profile: two concurrent detail reads, three concurrent image reads, one GPU OCR worker, lower-priority background workers, and GPU release after ten idle minutes.

Balanced and speed-first presets remain available. Advanced values are bounded by the approved browser and OCR capacities. Settings are read when a new Job freezes its execution parameters; running and historical Jobs retain their original values.

## Consequences

- Business interaction remains usable while capture and OCR run.
- Peak throughput is intentionally lower than the prior 4/6 profile.
- Historical acceptance evidence remains replayable because its stored concurrency is not rewritten.
