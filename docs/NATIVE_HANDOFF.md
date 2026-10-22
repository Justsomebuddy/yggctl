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

## Queue retention visibility

`alerts.jsonl` remains a bounded newest-suffix queue, not an indefinite durable
delivery spool. Appends compact at more than 1,200 rows to at most 1,000 rows,
or earlier when the 32 MiB byte limit requires it. Producer acknowledgement
means the event was queued at that time; it does not pin the event against
later retention. A long sender outage can therefore outlast queue retention.

When compaction removes ordinary records whose IDs lack a checkpoint in
`alerts-forwarded.json`, it increments `evicted_uncheckpointed_total` in a
reserved `ygg-queue-retention` metadata row. The metadata and retained suffix
are written in the **same atomic replacement**, not as two separate state files.
The row survives later compaction and occupies one of the retained slots:
after loss, a 1,000-row compacted queue holds at most 999 ordinary alerts.
Its maximum encoded size is reserved before selecting the byte-bounded suffix.
Invalid/duplicate metadata, a corrupt cursor, counter overflow or insufficient
space for the new record plus metadata abort compaction without replacement.
An append already fsynced before a count-triggered compaction failure remains
on disk; the command still fails visibly.

The count describes **eviction occurrences without a current local checkpoint**,
not distinct permanently lost messages. A pending producer replay can reinsert
and later evict the same ID again. An ambiguous sender attempt may have reached
the native profile without a cursor checkpoint. Legacy/first-run cursor entries
remain historical skip boundaries, not retroactive proof of delivery. Deletions
before this accounting was installed cannot be reconstructed. Deleting, rolling
back or restoring inconsistent state can invalidate the count.

The forwarder prints the cumulative value before processing and in its final
summary, including first-run initialization and an empty backlog. For example:

```text
remaining=0 evicted_uncheckpointed_total=202
```

This means the retained backlog is drained, while 202 record evictions were
observed without checkpoints. Automation must inspect both fields; an increase
in the cumulative count is the signal for new evictions. A historical nonzero
count alone does not force an error exit and an endless `Restart=on-failure`
loop. Forwarding errors and pending backlog retain their existing failure exits.
The metadata is local only: it is never handed to SimpleX, added to the cursor,
or counted against the 2,000-entry native attempt journal. External monitoring
must collect the command output if remote notification of retention is needed.
Do not downgrade to an older reader while retaining this new metadata format:
an older forwarder does not know it is metadata and may send a generic alert,
and older compaction can discard the counter. This source change does not
update an installation, external monitoring or integrity manifest.

## Historical state and delivery limits

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
