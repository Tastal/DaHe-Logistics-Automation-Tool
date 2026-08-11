# ADR-013: Module Modes

## Context

Modules need independent shadow validation and controlled migration from the legacy system.

## Decision

Give each business module one explicit mode: disabled, shadow, or operational. Production changes require a separate approved cutover checklist.

## Consequences

Running jobs freeze their mode. Upgrades and configuration restore cannot silently enable production behavior.
