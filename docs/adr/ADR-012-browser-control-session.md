# ADR-012: Browser Control Session

## Context

Automated navigation and human control cannot safely use competing ownership records for one Chengfeng session.

## Decision

Use one BrowserControlSession as the physical session authority, with a monotonic control epoch and fencing token.

## Consequences

Stale commands are rejected. Human control cannot be reclaimed by an ordinary lease timeout.
