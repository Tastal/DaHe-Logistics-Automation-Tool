# ADR-059: Warm browser session and stable task progress

## Context

The operational Chengfeng collector previously closed its isolated browser after every successful or empty capture. Reopening the runtime and restoring login state added avoidable latency. Task elapsed time could also continue after an empty result or terminal failure because terminal state and item counts were evaluated in the wrong order.

## Decision

The browser process lifetime is separated from the `platform_browser` resource lease.

After a successful or empty operational capture, the worker clears all job-scoped request bodies, signed image capabilities, pagination state and fencing tokens. It releases the resource lease and parks the isolated context without navigation or network activity. The process, DaHe profile and login state may remain available for the next task.

The runtime is closed only when DaHe exits, credentials are replaced or deleted, the browser or profile fails, or a security invariant cannot be re-established. A context previously handed to a person is rebuilt before any automated navigation. An expired login may be retried automatically once; CAPTCHA or repeated login failure requires one bounded human-login window.

Progress projections persist start, phase, update and finish timestamps. Terminal status is evaluated before counts. Success, failure, cancellation and an empty successful result freeze elapsed time and clear the remaining estimate. Non-terminal estimates require at least three completed items and five seconds of phase history. The frontend advances display time from the latest server anchor with a monotonic clock and must never move elapsed time backwards.

## Consequences

- A healthy second task avoids browser cold-start and profile initialization cost.
- An idle browser does not hold the platform resource lease and must not send background requests.
- Job-private request authority cannot survive into the warm session.
- Process supervision must still close the owned browser during application shutdown.
- Strict validation and human handoff continue to require their existing isolation and context-rebuild rules.
