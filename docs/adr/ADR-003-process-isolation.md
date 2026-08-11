# ADR-003: Process Isolation

## Context

Browser automation and OCR have different dependencies, resource use, and failure modes from the main application.

## Decision

Keep the main application, Chengfeng connector, and OCR workers in supervised process boundaries with versioned protocols.

## Consequences

Failures can be contained and resources reclaimed. Process ownership, heartbeat, and protocol compatibility must be tested.
