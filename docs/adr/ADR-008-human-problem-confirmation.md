# ADR-008: Human Problem Confirmation

## Context

Role conflicts and suspected swapped tickets require business judgment and must not block normal waybills.

## Decision

Machines only mark suspicion. A person confirms a problem. Shadow mode records only a local result; operational handling remains a separate approved human process.

## Consequences

Normal work continues. Suspected tickets are never swapped or passed automatically.
