# Ygg-only native-recorded handoff — source 5.9.0 (#9)

`telemetry.forward` no longer invokes the shared `simplex-alert.sh`. It calls
`simplex_sender.handoff` and advances the queue cursor only after a native-recorded
receipt. Process rc0, rendered CLI output and the shared bridge's rate suppression
are **never acceptance evidence**. Other alert chains/shared bridge are unchanged.

## Required external integration

Provision root-private `simplex-sender.json` under the console configuration
directory with exactly these fields (illustrative, not actual profile settings):

```json
{"database":"/var/lib/console-alerts/profile_chat.db","contact":"operator","binary":"/usr/local/bin/simplex-chat","user":"root","lock":"/var/lib/console-alerts/profile.lock"}
```

Use an already approved ordinary-SQLite profile pair and the **same flock inode
used by ALL writers/pollers** of it. A root-owned lock may be root-group
writable (0660); other writable groups/world write are refused. Lock custody
and trusted writers remain external prerequisites, not message authority. Never create a replacement identity, bypass
encryption or put passwords in this configuration/argv/environment. Config is
owner-private; database must be private to the configured run user; executable
must be trusted/non-setid/non-writable. Paths/ancestors, profile custody, binary
version, schema and shared-lock integration need operator qualification. Missing
config, encryption, incompatible schema, wrong/ambiguous active-user contact or
unsafe files fail closed, leaving alerts pending. No fallback to process rc0.

The numeric-contact command is `/_send @ID json [...]` in native one-shot `-e`
mode with explicit profile prefix. The message contains a stable SHA256 event-ID
marker and exact rule/body text. Input/body/query/process/lock time are bounded;
command output is not parsed or persisted. A guarded child retains the profile
lock, arms Linux parent-death SIGKILL after identity selection and checks its
original parent before exec. The process runner kills/reaps its process group
on timeout. This is Linux-specific, not a portable lifecycle guarantee.

## Operator outbound pause (5.12.4)

The native adapter bypasses the legacy shared shell sender, but must not bypass
an operator's hold on the same profile. It checks `outbound.paused` in the parent
directory of the configured `lock`, under that same profile lock, before any
native lookup, attempt-journal write or CLI launch. No configuration fields or
existing profile bindings change. This fixed sidecar name is part of integration:
if a shared sender uses another pause path, align that external integration first.

An existing marker must be a regular non-symlink file owned by the invoking
privileged operator, with no group/other permissions. Contents are not interpreted.
Unsafe markers or metadata errors fail closed; even a dangling symlink is unsafe.
An absent marker preserves the native receipt protocol below. This is a sampled
hold check, not atomic cancellation of a child already launched before the hold.
All writers and the hold controller still require trusted custody/coordination.

`alerts-forward` stops at the hold and prints `state=paused deferred=N`, with
`remaining=N` retained and no receipt/cursor advance for deferred items. A purely
paused run returns zero as an intentional deferral, **not delivery success**;
monitor the state and remaining count, not just the service exit code. An earlier
handoff failure in that same run still returns nonzero. A hold appearing between
events preserves already committed receipts and defers the rest.

This console never removes the marker. Only an explicit operator release of the
hold, followed by `alerts-forward` or a new queue path activation, resumes work;
there is no pause-file watcher or automatic resumption guarantee. Existing
ambiguous attempts still require evidence/operator review after release and are
never reset or retried merely because the marker disappeared. A pause does not
cancel pending agent transports in a profile opened by another process.

## Durable protocol and failure semantics

1. Under the profile lock, read native state query-only in one SQLite snapshot.
   Require exactly one configured direct contact for the active user. A matching
   outgoing native item must have the exact marker AND body, native text payload,
   direction, no group/forward/edit/deletion and a positive native item ID.
   Conflicting/duplicate rows are errors, never a reason to resend.
2. Bind an event to its actual text digest and profile configuration/database
   device+inode/native user+contact identity. Existing durable accepted receipts
   are historical recording evidence and can be reused without another send
   if the original row is now absent. A currently conflicting/edited/soft-deleted
   matching marker still fails closed before receipt reuse. Profile replacement/restore,
   config/contact change or different text for the same ID fails closed.
3. Fsync an `attempted` journal entry **BEFORE** launching the native CLI. On
   every result, including timeout/error, reread native state. A qualified item
   becomes a fsynced `native-recorded` receipt; only then can the forwarder commit
   its cursor. A crash between receipt and cursor commit recovers without resend.
4. **No item after an attempted launch means AMBIGUOUS, not safe-to-retry.**
   Network acceptance can precede local item persistence. Later runs may find
   native proof and recover, but NEVER blindly launch that event again. Even a
   crash between intent commit and exec conservatively blocks automatic retry.
   A handled command error returning rc0 therefore cannot falsely advance the
   cursor. This deliberately trades availability for avoiding automatic duplicates.

`simplex-attempts.json` is private, atomic/fsynced, bounded to 2,000 entries/1 MiB,
with no automatic eviction/reset. Capacity/corruption blocks new attempts rather
than discarding deduplication evidence. Preserve it with the profile and cursors.
Do not delete ambiguous intents to unblock a queue: an operator must investigate
native/transport evidence and explicitly accept any new-event/resend risk.
No automatic ambiguity-resolution or journal rollover command is implemented.

Existing legacy cursor entries/first-run history boundary are preserved, NOT
retroactively verified or resent. Historical process-only checkpoints do not
become native receipts. The journal is not an adversarial-profile/compromised-root
boundary and cannot survive deliberate deletion or inconsistent backup rollback.
There is **no exactly-once remote delivery, guaranteed delivery or human ACK**.
These are separate contracts; a locally recorded outgoing item is not either.

See [the historical shared-bridge audit](SIMPLEX_BRIDGE.md) for the replaced
process-only behavior. Reference-source publication does not configure or update
an installed console/profile. Isolated native/profile-copy qualification, when
reported, is not a real recipient/delivery test.
