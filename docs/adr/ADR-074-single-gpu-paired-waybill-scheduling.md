# ADR-074: Use one GPU Worker with paired waybill scheduling

## Context

The offline review scheduler previously processed many loading images before unloading images. Total GPU throughput was acceptable, but the first complete vehicle could be delayed behind a long loading-side queue and the vehicle progress shown to the operator did not advance intuitively. Starting a second GPU Worker would compete for memory and could reduce stability and throughput.

## Decision

Keep one persistent GPU Worker and one `gpu_ocr_slot`. After one side of a waybill completes, the other incomplete side receives one pairing priority. The scheduler persists both image results and the vehicle decision before advancing the completed-vehicle progress. It then returns to the existing fair cross-job selection so another job cannot starve.

Shared image evidence is reused without another OCR call. A missing side is finalized through the existing human-review contract. If an allowed GPU technical failure requires CPU fallback, any incomplete GPU pair for that vehicle is discarded and both available sides are rerun on CPU; no mixed partial pair is published. Pause, cancellation and recovery remain durable at image and vehicle boundaries.

The acceptance gate forbids extra OCR calls, artificial sleeps or a second GPU process. On the same sanitized fixture, total duration may not regress by more than five percent and the first completed vehicle should appear substantially before the whole batch.

## Consequences

- Vehicle progress follows the frozen waybill order and becomes visible earlier.
- GPU memory usage remains bounded by one qualified Worker.
- Cross-job fairness is preserved at completed-vehicle boundaries.
- Pair fallback is more expensive only on a technical failure and avoids combining incompatible GPU and CPU evidence.
