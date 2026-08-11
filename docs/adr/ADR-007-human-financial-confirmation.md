# ADR-007: Human Financial Confirmation

## Context

Settlement confirmation and payment are irreversible financial actions.

## Decision

Settlement confirmation and payment remain permanently human actions on Chengfeng.

## Consequences

The application may prepare and validate a handoff but must not expose an automated settlement or payment endpoint.
