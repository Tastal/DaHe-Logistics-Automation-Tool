# ADR-065: Visible business page and fresh controlled reads

## Context

The long-lived Chengfeng profile can retain stale single-page application state even when the account has new waybills. The previous human-plus-controlled-tab design also made duplicate Chengfeng pages visible and was difficult for staff to distinguish.

## Decision

DaHe owns exactly one Chengfeng tab in its isolated profile. Starting settlement selects `/billablewaybill`; starting the daily workflow selects `/wayBill`. A minimized Edge window is restored and the tab is selected. Existing same-origin duplicates are closed; unrelated tabs are untouched.

Each read installs a fresh job-owned request capability on that same tab. Before either business creates its authoritative query, the worker disables HTTP cache, clears browser cache and reloads the fixed entry through CDP with `ignoreCache=true`, while preserving cookies and storage. A first authoritative zero triggers exactly one more full refresh and query in the same tab. The second zero is accepted. Daily refreshes preserve the page-owned private baseline and never click Reset.

On success, empty result, failure or cancellation, DaHe removes private request authority and leaves the single page on the selected business route.

## Consequences

- Staff can always see the corresponding Chengfeng page without duplicate platform tabs.
- Automated reads cannot trust existing filters because every job performs a cache-disabled reload and rebuilds its authoritative query.
- Stale cached page state cannot become the authority for a new capture.
- A fresh request capability and the existing deny-by-default firewall preserve read isolation on the shared page.
- Browser visibility and refresh failures stop before evidence capture instead of falling back to stale state.
