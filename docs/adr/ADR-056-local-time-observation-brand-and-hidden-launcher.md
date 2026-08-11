# ADR-056: Local time observation, brand, and hidden launcher

## Decision

When the platform does not provide unloading time, the daily projection may derive it from an unloading-ticket OCR observation explicitly labelled as tare or return-tare time. Printing and gross-weight times are excluded. Manual revisions remain authoritative.

The production interface uses the approved DaHe logo and the product name `大禾物流自动化平台`. The standard Windows shortcut starts the release through a hidden launcher, while an explicitly named diagnostic script keeps console output available for maintenance.

## Reason

The daily report requires a useful unloading-time default without guessing from unrelated timestamps. A hidden standard launcher prevents a console window from confusing business users while retaining a simple diagnostic path.

## Consequences

- Time-only OCR observations are anchored to the applicable business date and may roll into the next day.
- The stored machine observation keeps seconds; the Excel projection still truncates to minutes.
- The standard launcher depends only on Windows Script Host and the release-owned virtual environment.
- The diagnostic launcher is not used by the desktop shortcut.
