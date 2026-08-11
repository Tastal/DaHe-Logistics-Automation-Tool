# ADR-002: SQLite Data Foundation

## Context

The system runs on one Windows production computer and needs durable, queryable local history.

## Decision

Use SQLite as the production data foundation with one coordinated writer, WAL mode, foreign keys, short transactions, migrations, and verified backups.

## Consequences

The application avoids a separate database service. Long transactions and uncoordinated writers are prohibited.
