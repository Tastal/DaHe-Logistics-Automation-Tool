# ADR-019: Do not attribute business actions to people

## Context

DaHe is used on one company computer by a small business. Requiring names,
employee numbers, reviewer identities, or operator switching adds configuration
and form work without supporting a business decision the company needs.

Earlier Loop 7 tooling bound some review evidence to a configured reviewer.
Those sealed files and hashes must remain reproducible, but the active product
must not continue that identity contract.

## Decision

- The product does not create accounts or collect names, employee numbers,
  operators, reviewers, action owners, or other human attribution.
- Manual actions record business values, reasons, optional notes, timestamps,
  evidence identities, versions, and state transitions only.
- Jobs, work items, actions, sessions, instances, record versions, and
  diagnostic codes remain technical identifiers and must not be presented as
  people.
- Windows ACLs, DPAPI, local-session protection, and maintenance authorization
  may use operating-system security context without copying a username or SID
  into business data, evidence, ordinary diagnostics, or user interfaces.
- New evidence schemas do not contain human-identity fields or hashes.
- Sealed Loop 7 evidence remains byte-for-byte unchanged. A read-only legacy
  verifier may parse its old reviewer fields only to reproduce existing hashes;
  it must not copy them into active records or new evidence.

This decision supersedes human-attribution requirements in earlier product
guidance and identity-related clauses in ADR-014 and ADR-016. It does not weaken
idempotency, record-version, local-session, or maintenance-security controls.

## Consequences

The console has no operator setup or switching flow, and finance users do not
enter identity data. Historical timelines can explain what happened and when,
but not who performed a manual action.

The system cannot provide per-person accountability or staff productivity
reports. DaHe accepts that limitation. Technical recovery remains possible
through immutable evidence, action IDs, timestamps, versions, and diagnostics.
