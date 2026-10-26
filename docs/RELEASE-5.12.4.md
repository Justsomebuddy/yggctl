# Source 5.12.4 — respect native-profile outbound holds

The native handoff adapter bypassed the shared shell sender and consequently
ignored its operator pause. This release checks a trusted `outbound.paused`
sidecar next to the configured shared lock before accessing the native sender.
No config schema, journal binding, receipt or deduplication protocol changes.

A deliberate hold is displayed as `state=paused` with explicit deferred/remaining
counts; its zero exit means intentional deferral, not successful delivery.
Unsafe markers and any earlier handoff failures remain real errors. A hold
between events retains already committed receipts and defers all remaining work.

Five new synthetic regressions cover no native access/no journal mutation,
unsafe marker custody, ambiguous intents surviving pause/release without retry,
mid-run hold and non-masking of earlier errors. The original source fails the
no-native-access hold regression. All nine configured QA gates pass: 591 tests, 4658 statements and 1702 branches
covered at 100%, with zero excluded or missing lines/branches. Separate standard
library suites overlap that total; source QA is not installed-runtime evidence.

No hold is cleared, old event resent, message deleted or profile replaced.
A native recording receipt is neither remote delivery nor human acknowledgement.
Operational errors from earlier ambiguous sends cannot be reconstructed from
process status alone; this change does not claim to repair their transport.
See [integration and resumption requirements](NATIVE_HANDOFF.md#operator-outbound-pause-5124).
