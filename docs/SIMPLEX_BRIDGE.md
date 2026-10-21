# Historical shared bridge — through source 5.7.9

**Source 5.9.0 supersedes this for Ygg forwarding:** see [native handoff](NATIVE_HANDOFF.md).
The shared bridge itself remains unchanged for its other consumers. The audit
below describes the old implementation, not the new adapter.

# Actual SimpleX bridge contract (issue #9)

This describes the existing deployment bridge, not a new sender backend or an
installation recipe. Private contact names, profile locations, credentials and
service accounts are deliberately omitted. The public repository does not
install `simplex-alert.sh` or provision a SimpleX profile.

## Inspected version and mode

On 2026-10-21 the operator's binary reported **SimpleX Chat v7.1.0.3**.
The bridge uses the **one-shot native CLI**, not the WebSocket API:

```text
timeout -k 2 10 SIMPLEX_BINARY -d PRIVATE_PROFILE -e "@CONTACT MESSAGE"
```

It may run that command under the configured profile account. The native CLI's
stdout is discarded. Stderr is captured only to record whether it was nonempty;
its content is not treated as a structured command result. The wrapper decides
success solely from the process exit code. A `SENT/status=delivered` log label
therefore means **process success**, not independently verified native command
acceptance, SMP delivery, device receipt or human acknowledgement. Do not use
that label as evidence for those stronger claims. No claim is made that this
binary corresponds to the upstream commit examined in the issue.

## Credential-free algorithm of the inspected wrapper

1. Parse the input JSON. Emergency/Alert/Critical require a separate human-ACK
   workflow; Error/Warning do not. Other priorities are dropped with exit 0.
   Current Yggctl peer alerts/test use Warning; health alerts use Error.
2. Compute an event key from priority, rule, and any selected `output_fields`:
   user/process/file/socket/container identity fields. Serialize that identity
   canonically and SHA-256 it. Yggctl currently supplies no `output_fields`, so
   its bridge suppression identity is **priority + rule**, not the queue ID,
   message body, timestamp or native SimpleX message ID.
3. Take the wrapper's shared file lock (finite acquisition timeout). An existing
   same-key pending ACK record for an ACK-requiring priority suppresses with
   exit 0. A recorded same-key rate timestamp younger than the configured
   interval (default **300 seconds**) also suppresses with exit 0.
4. Build the message. For ACK-requiring events, atomically create the pending
   record before invoking the CLI. Input/build/lock/pending errors are nonzero.
5. Invoke the bounded one-shot CLI above. On a nonzero process status, remove
   that attempt's pending ACK record, do not start the rate window, and return
   the failure. Yggctl retains its uncheckpointed queue ID for another attempt.
6. On process status 0, try to record the rate timestamp, log `SENT`, and return
   0. A failure to commit that timestamp is a warning but still returns 0 to
   avoid knowingly requesting another send. No native message ID is saved.

This is a description of the inspected implementation, not a recommended
idempotent-delivery reference implementation. It intentionally preserves the
important distinction between actual code and the stronger protocol one might
wish it implemented.

## Direct answers to the two scenarios

- **Handled command error + process exit 0:** yes, the wrapper can return 0 and
  Yggctl can checkpoint the queue ID without successful native command
  acceptance. Neither component parses/validates that command response. Rate
  suppression also returns 0 without a new send. This is a real limitation of
  the inspected algorithm, not proof that an installed notification was lost.
- **Native acceptance followed by wrapper failure/timeout:** the queue ID stays
  pending. Retrying can create another message. A committed rate timestamp may
  suppress a nearby retry, but it is not stable per-event/native idempotency;
  acceptance before rate commit, rate-write failure, an expired window and the
  checkpoint crash window leave duplication possible. No claim of a live
  duplicate observation is made.

Yggctl source 5.7.9 makes the CLI disclaimer explicit: sender rc0 is **not
command acceptance/delivery/human ACK**. Offline boundary tests deliberately
show the existing checkpoint/retry semantics, including synthetic rc0 command
error and accept-then-timeout. These tests do **not** execute a real profile,
prove the CLI's upstream behavior, or repair its transport semantics.

A stronger adapter remains separate work: require structured command acceptance,
associate stable event IDs with native items, resolve ambiguous timeout results
before resending, and define retention/deletion/recovery and writer-lock rules.
It needs independent native CLI/DB schema, crash, lifecycle and concurrent-writer
qualification before any profile migration. A command response or local item is
still not delivery or human ACK. The shared bridge and unrelated alert chains
are not changed by this source release.
