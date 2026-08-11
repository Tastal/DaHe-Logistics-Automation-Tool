# ADR-010: Dispatch Placeholder

## Context

Dispatch depends on an Android application, private VPN routing, and business rules that are not yet validated.

## Decision

Reserve a product and module boundary for dispatch without implementing or enabling real dispatch in the first MVP.

## Consequences

Current work cannot create plans, bind vehicles, or submit dispatch actions.
