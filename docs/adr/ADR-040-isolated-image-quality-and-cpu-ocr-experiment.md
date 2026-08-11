# ADR-040: Isolated Image Quality and CPU OCR Experiment

## Context

The production OCR direction remains local PaddleOCR with a GPU-first and CPU
fallback path. Before adding another image-quality dependency or alternative
OCR engine, DaHe needs a small reproducible experiment using already-consumed
development evidence. A new production framework, a second OCR decision
contract, or changes driven by a future locked set would increase maintenance
and invalidate acceptance evidence.

## Decision

Evaluate two current, maintained open-source packages outside every production
runtime:

- CleanVision 0.3.7 for development-only image quality characterization.
- RapidOCR 3.9.2 with Microsoft ONNX Runtime 1.28.0 for an alternative CPU OCR
  timing and ordinary-net recall signal.

The direct CleanVision, RapidOCR, and Windows x64 CPython 3.12 ONNX Runtime
wheels are pinned by official SHA-256 values. Each tool has its own AppData
virtual environment and a checked-in exact package inventory. Installation
does not change the main application, browser, CPU Paddle, or GPU Paddle lock.

The runner accepts only absolute, nonsymlinked protected Loop 7 development
records. It verifies the authority location, content-addressed image identities,
human labels, and image bytes. It does not accept a web or platform weight. A
quality-aware deterministic sample includes existing reviewed quality
conditions before filling remaining positions by image hash.

Worker output is deliberately narrow. RapidOCR text stays inside the isolated
process and is reduced to normalized numeric candidates. Saved evidence keeps
only hashes, quality flags, timing, candidate counts, and truth-match booleans.
Temporary image copies are deleted after each run. Results always state:

- `development_only=true`
- `formal_acceptance=false`
- `future_locked_set_eligible=false`
- `production_promotion_allowed=false`

## Result and consequences

The representative 20-image development run included all eleven existing
quality labels. RapidOCR matched the human ordinary-net truth on all 17 images
where a truth value existed. Its median image time was about 0.85 seconds,
compared with about 15.4 seconds for the historical CPU Paddle observations in
the same sample. This is a development recall signal, not role accuracy,
end-to-end audit accuracy, or a production benchmark.

CleanVision's default rules flagged none of the 20 images, including the sample
already labelled blurry. DaHe will therefore not add CleanVision to ingestion
or automatic review routing. Threshold tuning is not justified by this small
consumed set.

RapidOCR remains a promising development candidate, but the current Windows
release requires two explicit compatibility measures: a string model-root
parameter and a separately installed ONNX Runtime backend. It must not replace
PaddleOCR until a later isolated experiment covers role extraction, the full
field contract, failure routing, CPU/GPU comparison, and an independent data
gate. Loop 9 remains in progress and no Ledger acceptance state changes.
