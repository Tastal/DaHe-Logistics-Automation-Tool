# ADR-006: Browser Separation

## Context

The local console and Chengfeng automation have different security and lifecycle needs.

## Decision

Open the local console in the system default browser. Use a dedicated, controlled browser profile for Chengfeng.

## Consequences

The user keeps their normal browser preferences. Chengfeng control, profile data, and recovery remain isolated.
