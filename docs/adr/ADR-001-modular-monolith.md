# ADR-001: Modular Monolith

## Context

The product has one local installation, a small user group, and several workflows that share evidence and business records.

## Decision

Use one modular application with explicit module boundaries. Isolate OCR and browser automation in supervised processes only where runtime or failure isolation requires it.

## Consequences

Deployment stays simple. Module boundaries and dependency tests are required to prevent a new large monolith.
