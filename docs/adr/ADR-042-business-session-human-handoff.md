# ADR-042: Business Session and Human Handoff

## Context

The operational compatibility connector must support daily work without making
staff repeatedly confirm the same safety facts or closing the Chengfeng window
after each read. The browser may remain useful for direct human settlement work,
but an automated connector must never resume navigation on pages that a person
has used under writable platform permissions.

The strict Loop 9 connector has different evidence semantics. Formal validation
must end before the browser is handed to a person for normal platform work.

## Decision

Add one lightweight `BusinessConnectionSession` to the existing browser-control
and job system. It is bound to the current build, application instance, and DaHe
browser session for at most twelve hours. The initial start records one safety
confirmation. Each read still creates a new existing Job, access window,
snapshot, checkpoints, and evidence.

Use this fixed control sequence:

```text
human login
-> explicit hand to program
-> automated read-only capture
-> automatic human handoff
-> human platform use
-> explicit reread or close
```

After a successful, empty, or failed operational capture reaches a safe
terminal boundary, erase the worker-private request authority, reopen the fixed
Chengfeng entry, revoke every automated fencing token, and enter
`human_handoff`. Do not close the browser. Expiry prevents another automated
read but does not close a window held by a person.

Before a reread, destroy or rebuild the browser context used by the person,
install the deny-by-default read boundary again, and create a new Job. Never
overwrite an older snapshot. A physical browser close, DaHe shutdown, or browser
failure ends the business session.

Human settlement or payment actions performed directly on Chengfeng are outside
DaHe's capability and evidence. DaHe neither triggers nor records them. A strict
validation run cannot enter business handoff; if control is handed to a person,
that formal evidence run ends and cannot satisfy a Loop 9 gate.

## Consequences

Daily users can keep Chengfeng open after data collection and can perform another
read without repeating the working-day confirmation. The implementation reuses
the existing scheduler, access windows, browser authority, and audit pipeline;
it does not add a second state machine or connector fallback.

Rereads pay the cost of rebuilding a safe browser context. This is intentional:
it prevents stale human-page state and old fencing tokens from becoming automated
authority. Operational evidence remains separate from `shadow_accepted` formal
evidence.
