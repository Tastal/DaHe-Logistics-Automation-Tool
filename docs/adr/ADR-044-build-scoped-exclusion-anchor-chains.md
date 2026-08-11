# ADR-044: Build-scoped Exclusion Anchor Chains

## Context

Loop 9 binds every formal exclusion authority to the source boundary, identity
context, current build, selected settlement and daily contracts, and their
selection records. The original SQLite anchor used a globally unique sequence.
After a legitimate build rollover, the new file chain had to start at sequence
one while the database still retained the previous immutable chain. The global
key rejected that valid rollover and encouraged unsafe deletion or restoration
of an older database.

## Decision

Partition exclusion anchors by a canonical authority-context SHA-256 derived
from every formal binding. Sequence numbers and child-inventory uniqueness are
scoped to that context. Node hashes remain globally unique, and update and
delete triggers continue to make every stored row immutable.

Migration preserves every existing anchor and derives its context without
rewriting the node payload. A new build or contract selection starts a new
sequence-one chain. The current file authority remains a single complete chain
for the active context; superseded file chains and pre-migration databases are
retained in the DaHe data root for audit and recovery.

## Consequences

- Build and contract rollovers no longer require deleting formal history or
  restoring a stale application database.
- A loader queries only the exact current authority context and still verifies
  the complete file chain against its immutable SQLite anchors.
- Old anchors remain available as evidence but cannot authorize the current
  build.
- Downgrading the migration is intentionally rejected because it could only
  represent one context by discarding immutable history.
