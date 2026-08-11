# ADR-054: Daily probe and target range separation

## Decision

The daily read contract separates structural discovery from the requested business range. `prepare_daily` validates the fixed host, path, method, field names, field types, and response shape. Its probe date is not an authority over the business date selected by the user.

A target daily read may replace only the validated start time, end time, and approved location keyword. The range must remain one Beijing business day from 14:00 through 14:00 the next day. A target that exactly matches the probe can reuse the probe response; another valid date performs one new read-only query. Unknown fields, invalid ranges, unapproved locations, response-shape changes, redirects, and platform writes remain denied before sending.

## Consequences

- A valid historical business day no longer fails because it differs from the discovery date.
- Structural contract drift is still detected independently of business values.
- The stateful page twin must cover both exact probe reuse and a different valid target date.
