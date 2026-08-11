# ADR-009: Structured Retention

## Context

The company needs a durable data foundation while ticket images consume significant storage.

## Decision

Retain structured business data and audit history long term. Images become eligible for controlled cleanup only after the documented retention and hold rules pass.

## Consequences

Historical decisions stay queryable even when eligible source images are later removed.
