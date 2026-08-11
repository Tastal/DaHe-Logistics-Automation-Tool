# ADR-005: Independent OCR Extraction

## Context

Using the platform weight to choose an OCR candidate can hide recognition errors and create false passes.

## Decision

Extract ticket fields independently. Compare the structured OCR result with the frozen platform snapshot only afterward.

## Consequences

OCR evidence remains auditable. The platform expected weight is forbidden from OCR candidate selection and cache identity.
