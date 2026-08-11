# ADR-014: Local API Consistency

## Context

The operator console must survive refreshes and concurrent local actions without
inventing business state in the browser or losing committed task changes.

## Decision

The backend is authoritative for job projections and action availability.
Local writes require a session token, an idempotency key, and an expected record
version when an existing record is changed.

SQLite state and its event outbox are committed through the shared short
transaction gate. The event stream is only a change notification: clients first
load a complete snapshot, reconnect from a cursor, and reload authoritative
state after each accepted event.

The frontend build and backend application version must match before business
state is read or changed. Loop 4 replaced the temporary initializer with the
single Alembic-managed database. Earlier temporary development databases remain
isolated and are not migrated implicitly.

## Consequences

Refresh and duplicate submissions are recoverable, stale writes are rejected,
and the frontend does not maintain a second business state machine. Every state
change requires a durable event, and schema changes require checked-in
migrations and pre-migration backup.
