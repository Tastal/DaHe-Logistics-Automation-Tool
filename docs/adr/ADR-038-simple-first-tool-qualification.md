# ADR-038: Simple-First Tool Qualification

## Context

DaHe serves one small company on one production Windows computer, with a second
computer used for development. The Chengfeng connector, OCR runtimes, local
console, evidence store, and job engine already create several necessary
boundaries. Adding a general observability platform, container stack, another
browser framework, or overlapping OCR framework could make diagnosis and
deployment harder than the problem it solves.

Some focused third-party tools can still reduce risk. Examples include a secret
scanner for release checks, a dependency vulnerability auditor, an optional
process profiler, a maintained Windows installer builder, and a verified backup
client. These tools have different trust and runtime requirements and must not
become implicit production dependencies.

## Decision

Use a simple-first qualification gate for every new tool:

1. Name the observed problem and a measurable acceptance result.
2. Check whether the standard library, the existing dependency set, or a small
   project-owned implementation is sufficient.
3. Accept only an official, actively maintained project with a compatible
   license and explicit Windows support.
4. Pin package versions. Pin downloaded executables by SHA-256 and keep them
   under DaHe's per-user AppData development-tools directory.
5. Keep scanners, profilers, API fuzzers, experimental OCR engines, installers,
   and backup clients outside the main application and OCR environments.
6. Run first against frozen offline fixtures or approved development evidence.
   Network absence is reported as not run, never as passed.
7. Document removal and Git rollback. Remove an experiment that produces no
   objective benefit.

The default architecture remains a local modular monolith. Do not add
microservices, containers, message brokers, a general telemetry backend,
Selenium, a second scheduler, or an autonomous browser agent for the current
scope.

Chengfeng settlement counts are runtime observations. No observed value,
including 121, may become a product constant or acceptance threshold. A single
capture freezes its first successful total for pagination consistency; a later
capture may legitimately have a different total.

## Consequences

Development tools can be upgraded or removed without changing production
business behavior. Installation and backup tools remain explicit delivery
steps instead of background services. The project may decline popular tools
when their operational cost exceeds their verified benefit.

This decision does not accept the operational compatibility connector, advance
Loop 9, or authorize real Chengfeng access. Those gates remain independent.
