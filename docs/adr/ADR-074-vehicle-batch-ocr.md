# ADR-074: Use one ordered vehicle batch as the OCR commit boundary

## Context

The v1.1.3 scheduler treated each ticket image as a separate work item. This kept the OCR protocol small, but a vehicle could not become visible until both of its independently scheduled sides had finished. A first v1.1.4 attempt added scheduler continuation priority between two single-image calls. That preserved one GPU process but still paid repeated Worker setup and quick-stage overhead, and user acceptance found its latency and connection behavior worse than v1.1.3.

The earlier standalone audit program showed the useful product behavior: keep one GPU model resident, recognize both tickets for one vehicle together, and publish that vehicle immediately. Its use of platform weight to influence OCR candidates is prohibited and is not adopted.

## Decision

OCR protocol v2 adds `extract_batch` for one vehicle and one or two ticket images. Each input contains only an ordered role, content SHA-256 and data-root-relative path. Platform weight and other business expectations are forbidden. The persistent Worker sends all inputs through one common fast Paddle inference call and refines only a side that did not produce a reliable independent result.

The scheduler leases one GPU slot and one vehicle group. It persists all available OCR observations, completes the business decision and advances progress by one vehicle in one commit boundary. Completed vehicles appear in frozen waybill order. After a vehicle commit, normal cross-job fairness resumes.

An allowed GPU failure invalidates every uncommitted GPU result in that vehicle group. The CPU Worker reruns all still-required images for that vehicle as one group; a half-GPU, half-CPU vehicle is never published. Pause, cancel and recovery use the vehicle boundary. Existing v1 single-image commands and historical records remain readable.

## Consequences

- One persistent GPU process and one resource slot avoid competing model copies and excess VRAM use.
- A complete vehicle becomes visible as soon as its own evidence and decision are durable.
- OCR call count does not increase, while the common fast stage can process both sides together.
- Protocol and scheduler logic are slightly more complex because ordered group identity and atomic fallback are explicit.
- Performance acceptance must prove a real qualified GPU is primary, first ready-worker vehicle stays below 30 seconds, and the same fixture is no more than five percent slower than v1.1.3.
- ADR-004's one-image lease boundary is superseded for new operational OCR work; it remains the compatibility contract for v1 commands and historical tasks.
