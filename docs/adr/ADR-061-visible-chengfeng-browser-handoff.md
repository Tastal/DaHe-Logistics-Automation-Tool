# ADR-061: Visible Chengfeng browser with controlled read tabs

The production two-tab decision in this ADR is superseded by ADR-065. Historical formal discovery flows remain unchanged where they are explicitly isolated from the operational business path.

## Context

The production connector previously switched to a headless browser for automated reads and parked the session at `about:blank` afterward. This delayed later use, hid the session from business staff and conflicted with the requirement that the Chengfeng window remain available for ordinary manual work.

## Decision

DaHe maintains one visible Edge runtime with its own profile. Its long-lived human page is available to staff while idle and does not hold the `platform_browser` lease or produce automated requests.

Each approved read creates a new controlled tab and a fresh fencing token. Only that tab may perform the allow-listed read. On success, empty result, failure or cancellation, DaHe clears all job-private request authority, closes the controlled tab, releases the lease and retains the human page. A later read always creates a new controlled tab and never automates a page that staff have used.

The runtime closes only when DaHe exits, the connection is explicitly reset, the profile becomes unsafe or the browser crashes. A displaced login is retried once with the stored credential reference; CAPTCHA or a failed login leaves at most one visible login window.

## Consequences

- Browser lifetime and resource ownership are separate.
- Staff can continue using the isolated platform window between reads.
- Automated navigation cannot inherit mutable state from a human-operated page.
- Keeping the window visible does not authorize platform writes or relax the request firewall.
