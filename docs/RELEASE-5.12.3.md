# Source 5.12.3: missing peer observations

A collector that cannot acquire the shared lock never obtains a peer sample.
Counting the old down interval through that gap can produce a false duration.
This release retains the original contribution and adds independent regressions.

## Behavior and compatibility

The peer-alert state stores `last_observed` atomically with each actual observed
transition. The documented nominal cadence is one minute. A gap **greater than
120 seconds**, a backward clock or an invalid previous timestamp breaks downtime
confirmation. Exactly120seconds remains tolerated scheduling jitter, not evidence
that the peer was continuously unreachable between samples.

- Unalerted downtime restarts at the new sample; a new ten-minute confirmation
  requires subsequent observations. No invented samples are written after a
  failed lock acquisition; the lock timeout still returns its original error.
- Already-alerted episodes do not produce a duplicate down alert. Their eventual
  recovery discloses the observation gap instead of claiming continuous downtime.
- Pending events keep their original IDs and payloads, including queue retries.
- Legacy tracked episodes without `last_observed` receive one conservative
  transition. An unalerted episode can therefore require a fresh ten-minute
  confirmation after upgrading. Explicit unknown and ambiguous-label rules remain.
- Notification-off tracking remains active. Queue capacity or atomic state-write
  failure must not falsely advance the durable observation timestamp.

This is a sampling policy, not complete outage detection or clock authenticity.
Other collector schedules need an independently reviewed sampling policy.
Do not downgrade a state reader automatically: prior durable outbox, admission
and Atlas compatibility/recovery boundaries still apply.

## Verification and limits

The release gate is bound to the exact committed tree, not to this test-count
text. The local target includes586unique tests, seven independent freshness
regressions, the configured nine-stage quality gate and exact100% production
statement/branch coverage with zero exclusions. Consult the exact commit's
[Actions run](https://github.com/Justsomebuddy/yggctl/actions) for hosted results.
The separate93/24/33stdlib suites overlap that total, not150extra unique cases.

The independent causal test takes a real advisory lock in disposable fixture
state and waits for the real20s timeout. At the next sample eleven synthetic
minutes after the first down sample, the previous implementation emits a false
11-minute down event; this version restarts confirmation without that event.
Other cases cover microsecond boundaries, pending replay under queue EIO, legacy
migration, timezone equivalence/rollback, failed atomic state writes and extreme
previous timestamps. Fixtures do not operate host services or external peers.

A source/CI pass is not an installed-version, live-node, real SimpleX delivery,
human-acknowledgement, full-system-health or production-rollback qualification.
No change to Research timestamp interpretation is included.

See [architecture](ARCHITECTURE.md) and [interaction contracts](UI_MAP.md).
