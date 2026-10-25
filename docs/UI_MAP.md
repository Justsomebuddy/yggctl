# Historical report interaction contract

## Outbound QUIC runtime evidence

`check`, mode status and `mode direct|tunnel` retain their existing prerequisites.
An unchanged-mode request still probes runtime state without restarting services.
QUIC URI acceptance now agrees with the socket and underlay gates: a process-owned
UDP UNCONN socket may contribute only when its local port/bind has a unique
original-direction IPv4 conntrack tuple to an active configured QUIC peer with
its pinned key. Compare the daemon's query-free remote URI with the configured
endpoint/path; do not require the daemon to echo query parameters.

Successful QUIC proof no longer needs a TCP peer. Removing the last TCP peer
leaves proven QUIC evidence usable. The listener gate still requires the single
STACK TCP listener on 127.0.0.1:1080 and rejects additional TCP listeners.
Unknown, shared, malformed or ambiguously matched own UDP sockets refuse with
`underlay_quic_*`; an unexpected destination/key or mode mark cannot be hidden
by a good TCP socket. Direct expects mark3905; tunnel preserves the existing
predicate mark !=3905, including nonzero marks. No addresses or keys are printed
in new diagnostics. Own connections count observed sockets, not delivered packets.

The proof samples ss, conntrack and admin API sequentially. Connection churn,
expired/stale records or reused/shared UDP ports may require retry after
convergence; an indistinguishable reused tuple is not historical FD attestation.
This does not establish actual VPN routing, absence of every leak or future
packet safety. No firewall rules, permissions or service configuration change.
Deployers must review the changed checks.py hash in their integrity manifest.
Compensation/recovery still retains its journal when proof refuses.

## Health alert recovery (unreleased)

With notifications on, `collect` saves a degraded observation's hourly health
alert in `alert-state.json` before appending it to `alerts.jsonl`. A failed queue
write remains a visible failure; a subsequent collection, including a healthy
one, replays the original ID, timestamp and errors. Pending and queued health
events share the existing hourly suppression rule. Notifications off defer
existing pending events and do not stage new ones.

Peer and health events share the 1000-event/1 MiB pending bounds. Invalid state,
unreadable queue, capacity or state-write failure can prevent staging; no history
backfill or unlimited delivery guarantee is introduced. Queue replay does not
send directly. `alerts-forward` still requires native-recorded evidence and
refuses an automatic resend after an ambiguous attempt. This does not establish
remote delivery or human acknowledgement. Older collectors cannot consume health
pending entries; drain with the new writer or preserve them before rollback.

Current source: **5.11.1**. Earlier dated sections below describe historical
behavior; the final section defines the current changed CLI contracts.

Released source: **5.11.1**. Earlier dated sections below describe historical
behavior. The following Atlas section describes an unreleased change.

## Atlas bundle publication

This unreleased extension builds on the export lock/recovery change below.
`atlas report` retains the private-store and integrity prerequisites and the
same result keys (`json`, `md`, `dot`, `html` and observed counts). New paths are
`atlas/atlas-<32-hex-id>/report.<extension>`. Consumers must follow returned paths;
top-level `atlas-*.json` globs cover legacy output only. HTML remains standalone.

Under the directory lock, the console validates the bounded export inventory,
then removes only validated unpublished staging directories and legacy atomic
temporaries. It writes all four formats inside a private `.atlas-stage-<id>`
directory and publishes that directory with one rename. Completed files and the
containing directory are synced before the parent-directory sync completes the
operation. A write failure before publication cannot expose a partial new bundle.
The CLI still returns a nonzero status and `FAIL`; no success paths or `[done]`
are printed on that path. A later retry validates and discards staging work,
then starts a new report; it never parses staging data as observations.

Staging cleanup accepts only private current-owner directories and the fixed
report filenames or reserved atomic temporary names, with regular private
single-link files. Unknown, unsafe, oversized inventories or cleanup errors
abort. Validation finishes before any cleanup. A simultaneous exporter receives
`atlas_export_busy`, preserving the active writer's staging directory. Database
acquisition and the collector retain their separate locks.

Staging cleanup opens the validated directory without following symlinks, checks
its device/inode identity, and unlinks only the validated basenames relative to
that open directory. It checks the pathname identity again before removing the
empty directory. A replaced parent or an unexpected added entry causes refusal;
cleanup never recursively walks unvalidated content. This is not an isolation
boundary against another process holding the same store owner's credentials.

Legacy flat files, including pre-existing incomplete sets, remain untouched and
consume their existing retention slots. Complete new bundles consume four slots;
the budget remains 256 finished-file equivalents. Staging does not consume this
finished-output budget. Existing retention exhaustion still requires deliberate
operator review; this change does not delete historical evidence or auto-migrate
it. A cleanup permission failure remains a visible error until permissions are
restored. Temporary space is still needed for all four files.

If the process exits or the parent sync fails after publication, a complete
bundle may remain despite a missing success response. It is preserved on retry;
exactly-once report generation is not promised. Atomic visibility is not proof
of durability after hardware power loss. Quiesce old exporters before deployment:
older scanners reject the new directories. Rollback must preserve or explicitly
archive new bundles before returning to an old scanner; do not delete them
silently. Source changes do not update installed manifests or authorize deployment.

## Atlas export recovery

The following describes the earlier flat-file recovery change. The bundle
publication contract above supersedes its per-file publication behavior for new
exports; legacy output remains readable and is not rewritten.

`atlas report` retains its existing prerequisites: a valid private Atlas store,
the integrity check and a consistent SQLite read snapshot. Successful output
still names the four JSON/Markdown/DOT/HTML files and reports observed counts;
world coverage remains unknown.

The process holds an exclusive nonblocking directory lock from export validation
through cleanup and all four writes. A simultaneous report fails explicitly with
`atlas_export_busy`; retry after the active report finishes. This lock is separate
from the Atlas database writer and collector locks, so it does not serialize
catalogue acquisition, crawling or collection behind report generation.

After a crashed export, the next report validates the entire bounded directory
before deleting abandoned atomic-write files. Only reserved `.yggctl-` names
with eight lowercase letters/digits/underscores, regular-file type, current
effective UID, mode `0600` and one hard link qualify. Unknown entries, unsafe
temporary files, directory limits and retention limits still fail closed; an
unsafe temporary gives `atlas_unsafe_temporary_file`. Cleanup errors abort the
report. Temporary data is discarded, never imported as observations or promoted
to a finished report. Completed reports and the SQLite database are preserved.

All cooperating exporters must use this lock. Quiesce old report processes
before adopting the change; it cannot protect a concurrent older or external
writer that ignores the lock. This source change does not update an installed
integrity manifest or authorize deployment. Four files are still published
individually: an interrupted report can leave an incomplete completed-file set,
and a retry creates a new report rather than completing that set. Retention
remains an explicit operator review, not automatic deletion of finished reports.

## 2026-10-20 — source 5.7.5

| ID | Invocation | Expected result | Bounds and failure behavior |
|---|---|---|---|
| CLI-RESEARCH-REPORT | `research report [1..72 hours]` | JSON/Markdown report with existing historical samples, quantiles and explicit gaps | Accept the collector's complete 10,000–12,000 record retention cycle before selecting the requested time window; over-limit/corrupt data remains unknown, not fabricated history. |
| IPC-RESEARCH-METRICS | Research worker requests saved metrics through its broker | Full supported raw file, without truncation or silent history loss after encoding | Raw limit 32 MiB; metrics reply limit is `4 * ceil(raw_limit / 3) + 12` bytes, including compact JSON and newline. Other admin replies retain 24 MiB. |

No new command, option, output schema, external request or automatic data cleanup.
These are synthetic offline regression contracts, not proof of any deployment's
systemd provisioning, privilege isolation or overlay connectivity.

## Sandbox command boundary (5.7.6)

All `atlas`, `research` and remote commands fail before worker launch when the
parent integrity check fails. Research broker requests stay local-only; Atlas
crawl retains its three remote debug reads. Command syntax/output is unchanged.

## Privacy and restore boundary (5.7.7)

| ID | Invocation/path | Expected result / failure |
|---|---|---|
| CLI-RESTORE-PREVIEW | `restore FILE` | Structural checks only, explicitly **NOT AUTHENTICATED**. Archive/sidecar/internal hashes do not prove origin; no config, integrity manifest, gate or service changes. |
| CLI-RESTORE-APPLY | `restore FILE --apply` | Explicit failure before archive reads, decryption or lock. Disabled until independent authentication AND integrity acceptance are designed/reviewed; encryption is not authenticity. |
| TELEMETRY-PEER | collect / peer alert / stats | Literal endpoint; only typed public pin/timing query options can remain. Other query data, userinfo, path and fragments are removed; invalid endpoints become `unknown-peer`. |
| ALERT-LEGACY | Existing queue/pending | Rendering protects raw legacy peer fields; histories/IDs/cursors are not rewritten. Private secret-bearing pending refuses copying into the group-readable queue and requires separate review. |

These contracts do not claim that previously persisted or externally sent data
has been erased, or that an authenticated restore implementation now exists.

## Unknown observations, bounded preview and worker trust (5.7.8)

| ID | Invocation/path | Expected result / failure |
|---|---|---|
| TELEMETRY-UNKNOWN | `collect`, unavailable node observation | Persist `peers_observed=false`, retain down/reconnect/cooldown tracking and mark an observation gap. Health remains degraded/nonzero; durable pending can still replay. |
| ALERT-GAP | Next observed sample | Unalerted downtime confirmation restarts at that sample. An already-alerted episode is not alerted down again; recovery carries `observation_gap=true` and text does not claim uninterrupted downtime. |
| TELEMETRY-EMPTY | Successful node observation returning no peers | `peers_observed=true`; normal observed-empty tracking/removal semantics, not an unavailable query or invented recovery. Stack-only failure does not erase a successful node observation. |
| TELEMETRY-AMBIGUOUS | `collect`, multiple rows sharing one public peer label | Retain projected rows/counts and `peers_observed=true`; persist `ambiguous_peer_labels` in sample errors and return existing degraded/nonzero status. With notifications on, the existing hourly health diagnostic applies. Do not infer down/up/reconnect transitions for those labels; unrelated peers and pending replay continue. No private URI path is exposed. |
| ALERT-AMBIGUITY-GAP | Duplicate label becomes unique again | Retain previous down/reconnect/cooldown state while ambiguous. Restart unalerted downtime confirmation on the first unique observation; an already-alerted label may recover once with `observation_gap=true`. This reports the now-unique label, not proof of uninterrupted availability or of which former link survived. No historical events or cursors are rewritten. |
| CLI-RESTORE-BUDGET | `restore FILE` structural preview | 4 MiB compressed / 8 MiB TOTAL decompressed TAR / 1 MiB regular member. Metadata/padding/trailing and concatenated gzip are counted before TAR parsing. Reject over-budget/corrupt input without host writes; apply remains disabled. |
| IPC-WORKER-PRINCIPAL | Sandboxed command launch | Historical5.7.8 shared UID only; superseded by5.8.0 below; [explicit limitations](SECURITY.md#worker-trust-principal-source-578-issue-7). |

Command syntax is unchanged. No history, pending payload, queue or cursor is
silently rewritten. Gap-aware alert fields are additive; ordinary uninterrupted
observations keep their previous alert wording. Offline fixtures do not qualify
a host's systemd boundary or an installation.

## History write and sender boundary (5.7.9; issues #9/#10)

| ID | Invocation/path | Expected result / failure |
|---|---|---|
| TELEMETRY-WRITE-BOUND | `collect`, append reaching 32 MiB before count rotation | Atomically retain the newest complete suffix including the new record, within both byte/count limits. Reject an oversized individual record or corrupt/over-bound existing file; never silently discard corruption. Retention can be shorter than 10,000 records. |
| TELEMETRY-WRITE-ERROR | History append fails while state/queue remain writable | Continue durable pending replay and observed/unknown peer-state processing; report nonzero `metric_write_failed_alerts_processed` after successful alert processing. No fabricated history or outage across unknown observations. Other storage failures can still prevent state/queue commits. |
| ALERT-SENDER-RESULT | `alerts-forward` | Process rc0 checkpoint only; final output explicitly says NOT command acceptance/delivery/human ACK. Existing best-effort suppression and duplicate/loss windows remain; no new backend/profile migration. |

Tests use bounded synthetic histories and sender outcomes, not live notification
or multi-day evidence. See the actual bridge algorithm and limitations in
`SIMPLEX_BRIDGE.md`. No new command or network policy.

## Role identity/native handoff (5.8.0/5.9.0; #7/#9)

| ID | Invocation/path | Expected result / failure |
|---|---|---|
| IPC-WORKER-PRINCIPAL | Sandboxed launch | Three distinct provisioned role users; kernel UID AND expected unified systemd cgroup required. Wrong-instance connection rejected before serving; no same-role store isolation claim. |
| ALERT-NATIVE-HANDOFF | `alerts-forward` | Cursor only after durable native-recorded receipt; stdout distinguishes local recording from delivery/ACK. Process rc0/no item stays pending. |
| ALERT-AMBIGUOUS | Retry after durable attempt but no proof | Nonzero/pending, no automatic second send; later matching native item can recover. |
| ALERT-CONFIG | Missing/unsafe/incompatible native config/profile/journal | Fail closed, no legacy sender fallback or cursor reset. |

CLI syntax is unchanged; help names separate role users. Installation requires
reviewed provisioning/migration; publication alone changes no installed runtime.

## Current changed interactions (5.10.0; 2026-10-22)

| ID | Invocation / precondition | Visible result and side effects | Error / limit |
|---|---|---|---|
| ALERT-REPLAY-OBSERVATION | `collect`, existing pending replay fails | Attempt atomic staging of the fresh transition or unknown-observation gap; keep stable pending IDs | Original replay failure remains nonzero; bounded staging/storage can also fail. No corrupt-queue reset or fake acknowledgement. |
| ALERT-REPLAY-FINAL | Replay appends events and may compact the queue | Re-read final queue, compare ID and full payload, sync queue/directory, acknowledge only retained matches | Evicted IDs stay pending; `alert_pending_retained_after_queue_rotation`. Read/sync failure does not clear pending. |
| ALERT-RETENTION-METADATA | `alerts-forward`, queue has experienced uncheckpointed evictions | Print `evicted_uncheckpointed_total` before work and in summary, even at `remaining=0`; marker never sent | Count is eviction occurrences, not unique undelivered events. Historical nonzero alone does not change exit status. |
| ALERT-RETENTION-CAPACITY | Count/byte compaction | Up to `keep` ordinary alerts plus one bounded `ygg-queue-retention` record; ordinary alert count is not reduced merely to reserve a count slot | Same 32 MiB byte cap; metadata bytes can reduce retained suffix under pressure. Reader/writer must upgrade together. |
| CLI-RESEARCH-RECOVERY | `research capture/map/diff/report`, safe abandoned atomic temp exists | Writer-owned directory flock protects actual writes/scans; remove only validated reserved temporary files after full directory validation | Busy store: `research_store_busy`; unknown/unsafe entries fail closed. Completed data retained. No whole-run or JSON/MD-pair transaction. |
| CLI-RESEARCH-TRUST | Capture/map/diff/report results, report JSON/Markdown and DOT | Generated `provenance.status=unverified_role_writable_history`, `authenticated=false`, `immutable_since_capture=false`; visible UNVERIFIED warning | No origin, immutability, signature or API-truth guarantee. File-supplied provenance is not accepted into snapshot schema 1. |
| CLI-RESEARCH-CAPTURE | `research capture`, including partial saved result | Print unverified-history and `acquisition=local_api_sequential_unattested`; successful result repeats these fields | Partial saved capture still raises its existing nonzero failure. Stable local keys/source `ok` do not authenticate observations. |
| CLI-RESEARCH-MULTILINK | Map/diff/report over keyless or repeated peer tuples | Preserve peer rows; graph aggregates links. Diff `changed` includes tuple link/up-link count changes and is row-order independent | No stable per-link identity; unknown sources remain unknown. Tree/path duplicate keys remain invalid. |
| CLI-IDENTIFIED-PEERS | `check`, `collect`, waits, `watch` | Count only raw `up is True` with a lowercase 64-hex key | Transport-only connections do not satisfy peer/convergence gates; this does not prove application liveness. Historical projected booleans are unchanged. |
| CLI-PEERS-SCORE | `peers-score` | Add `identified`, rank identified first then latency; print explicit ranking disclaimer | Raw `up` remains transport state. Ranking is not trust, reliability or application health. |
| CLI-COLLECTOR-FRESHNESS | `check`, collector gate | Require active timer/trigger evidence, accepted service status, regular nonempty metrics file age 0..900s | `collector_never_fired`, `collector_data_missing`, `collector_data_stale`, or strictly `collector_data_future_timestamp` for any future mtime. Metadata is not sample correctness. |
| CLI-ROLLBACK-PROOF | Failed peer/mode/config transaction after preimage restoration | Compensation then restored-underlay proof before journal removal; initiating action error remains primary | Failed compensation/proof retains `rollback_runtime_failed` journal, secondary error as cause; further mutations remain blocked. No live-leak inference. |
| CLI-RECOVERY-PROOF | `recover-transaction --apply` | Restore, restart/converge, integrity and underlay proof before journal archival | Failure retains active journal for explicit retry. Preview does not restart or probe underlay. No journal schema change. |
| CLI-PUBLIC-URI | Supported peer URI strings in config/output/journal-facing labels | Remove credentials, unapproved query/path/fragment metadata; retain only allowed typed public labels | Not a universal free-text secret detector; no purge of old files/logs. |
| CLI-PEER-COUNTERS | Raw admin peer counters | Accept supported finite nonnegative numbers; bool/string/NaN/Infinity and integers too large for finite-value conversion are rejected | Controlled `invalid_peer_counter`, not uncaught `OverflowError`; no automatic legacy-metric rewrite. |
| CLI-STATS-INDEX | `stats` / graph window | Indexed lookup, same sorted output, first duplicate and absent semantics | Extra index memory; no strict whole-algorithm linear-time or universal speed promise. |
| IPC-SANDBOX-UNIT | Detect own worker launch | Only exact unified `/system.slice/yggctl-sandbox-<role>-<id>.service` accepted | User-slice/suffix/nested matches rejected; kernel broker admission remains separately mandatory. |
| ATLAS-ZIP-BUDGET | Read approved repository ZIP response | Bounded member streaming before aggregation; 8 MiB aggregate bytes delivered by ZIP reader | `atlas_catalogue_decompression_limit`; no independent hidden-stream attestation, total-RSS bound or TLS-bypass claim. |

These changes add no command or network-policy permission. See
[release evidence and limits](RELEASE-5.10.0.md); source regression results do not
prove an installed node, live notification delivery or human acknowledgement.

### External migration / recovery refusal

This repository bundles no deployment hook. The reviewed external migration
contract coordinates queue reader/writer changes and quiesces the Ygg-only alert
path/service; shared SimpleX is not stopped or restarted. After 5.10 publication,
the hook conservatively refuses automatic downgrade to 5.9 even if a queue scan
currently finds no marker: an already-imported old writer is a race, not a safe
rollback proof. Reached runtime bytes/manifest, queue/cursor and exact preimages
are retained for separately reviewed quiesced recovery. Partial publication may
leave mixed bytes: keep affected workers stopped and do not invoke the CLI until
coherent repair and verification. A refusal is not successful
automatic rollback, and no queue/cursor reset is authorized by this contract.

Source 5.10.0 raw-peer checks have both named-consumer regressions and an inventory
guard for new direct literal `up` reads. The guard permits reviewed schema and
historical projections; it is not a blanket ban or a data-flow proof.
## Stored-history trend (5.11.0)

| ID | Invocation / precondition | Visible result / side effects | Error / interpretation limit |
|---|---|---|---|
| CLI-TREND | `trend [hours] [json]`; default 24, integer 1..72 | Text report and `[done]` on stdout. With final `json`, stdout is exactly one JSON report (including `insufficient_history`) and the successful `[done]` summary goes to stderr. No API request or file write; existing gates/alerts unchanged. `--trace` logs through the existing trace channel. | `json` must be last; duplicate hours/format or out-of-range arguments fail. File must be readable; otherwise existing privilege check applies. Failed trend commands emit `FAIL` on stderr with no JSON or success summary on stdout. |
| CLI-TREND-SPLIT | Bounded `metrics.jsonl` window | Sort timestamps; equal oldest/newest **sample-count** halves; drop odd middle row; median/MAD comparisons | Not equal elapsed-time halves, time-weighted uptime, statistical confidence or a live health gate. Duplicate rows still weight metrics; distinct timestamp count is shown. |
| CLI-TREND-LIMIT | Fewer than 8 distinct timestamps, span <30 min, no observed sample, >25% unknown observations, stale collector, malformed peer container, or no comparable observed metric | Aggregate `insufficient_history` with explicit reasons; individual metric detail retained | Error-free sample share alone cannot establish stable observed connectivity. No samples in the window remains the existing controlled failure. |
| CLI-TREND-FUTURE | Any valid future timestamp in the same bounded history snapshot | `future_samples` count, `collector=future_timestamp`, `future_samples_present`; aggregate insufficient | Future samples excluded from metric window, not silently accepted as fresh evidence. Future-only history cannot yield a report. No second history read. |
| CLI-TREND-COLLECTOR | Valid in-window timestamp series | `collector=fresh/stale`, latest age and median positive-interval cadence | Stale beyond max(10 minutes, 3×cadence). Fresh is relative to stored timestamps, not an authenticated collector health claim. |
| CLI-TREND-OBSERVATION | Exact `peers_observed=true` | Per-half `answered` counts; unavailable samples counted `unobserved`; error share covers all selected samples | An unavailable observation is not an invented absent/down peer. A half without known evidence is `not_comparable`. |
| CLI-TREND-AVAILABILITY | Projected endpoint rows with strict boolean `up` | Availability = true / present known-state rows; expose `present`, `answered`, `absent`, `invalid_states`, `observed`, `unobserved` | Absent rows are not down; integers/truthy strings are invalid states. This conditional sample share is not whole-window uptime or raw API/key proof. |
| CLI-TREND-RTT | Strict-true projected peer row, finite nonnegative RTT | Keep zero values; `rtt_ms` compares protocol router-response EWMA | JSON/text explicitly distinguish EWMA from link/application delay; missing/invalid RTT is not comparable, not fabricated zero. |
| CLI-TREND-NUMERIC | Untrusted history values including huge integers | Finite nonnegative values only; missing metric is null plus explicit `not_comparable` reason; rejection totals logged/reported | Arithmetic overflow has explicit `arithmetic_overflow`, not silent saturation/NaN/Infinity. No automatic rewrite/delete of history. |
| CLI-TREND-IDENTITY | Sanitized displayed endpoint labels | `peer_identity=endpoint_not_key`, label policy shown; first row per shown label/sample wins | Port changes split a series; unknown/sanitized-colliding labels can merge origins. Not stable per-link or verified peer identity. |
| CLI-TREND-AMBIGUOUS | At least one sample whose peer rows render to the same sanitized label (for example different WebSocket paths at one endpoint, or an option the sanitizer drops) | `ambiguous_labels` (sorted labels) and `ambiguous_peer_samples` in text and JSON; that label's `availability`/`rtt_ms` are null with `not_comparable=ambiguous_peer_label`; aggregate `insufficient_history` with the fixed `ambiguous_peer_labels` reason; other labels keep their verdicts | Rows sharing a label observe different links, so a series fused in sample order is not comparable and must not yield a drift verdict; same rule as the [alert contract](UI_MAP.md) for duplicate labels. `present`/`answered`/`absent` stay per label and still do not identify origins. |
| CLI-TREND-TRUST | Every generated text/JSON report | Generated `provenance.status=unverified_role_writable_history`, auth/immutability false and visible warning | Role-writable local history has no origin/authenticity/immutability/signature/API-truth guarantee. File contents cannot grant trusted provenance. |

Existing stats/graph behavior and history schema are unchanged. Source tests use
synthetic fixtures; they do not verify external network-stand, performance,
installed-runtime or upstream measurement claims. See [release scope](RELEASE-5.11.0.md).

## Events window and bounded output (5.11.1; 2026-10-23)

| ID | Invocation | Expected result | Bounds and failure behavior |
| --- | --- | --- | --- |
| CLI-EVENTS-WINDOW | `events [1..72 hours]`, default 6; existing root requirement | Query matching node/stack journal entries since the requested time; hours never double as a line count | Read-only; no service or journal mutation. `logs [N]` remains unchanged. |
| CLI-EVENTS-LIMIT | More than 1000 matching records | Return newest 1000 in journal-provided order (no independent realtime sorting); `truncated=true` plus `WARN events_truncated` on stderr | Query at most 1001 records as a bounded overflow probe; omitted count is unknown. Narrow the time window or use a reviewed external journal query for omitted history. Successful bounded inspection remains rc0, not a completeness guarantee. |
| CLI-EVENTS-OUTPUT | Empty, partial or exactly full window | Preserve `logs`; add `window_hours`, `limit=1000`, `returned`, `truncated` | Exactly 1000 returns `truncated=false`; metadata describes records returned by journalctl under current access/retention, not proof of a complete historical journal. Existing human completion line remains on stdout. |
| CLI-EVENTS-FAILURE | Invalid hours, journal command/byte/time failure, malformed journal JSON | Existing nonzero failure; no partial log projection presented as successful | Existing message redaction applies before output, including the overflow record. No extra privileges, unbounded reads or relaxation of byte/time caps. |

## Privileged state admission (5.12.0, 2026-10-24)

Root lock-taking operations and the config/key health gate reject unsafe existing
state with `untrusted_state_custody`, `state_extended_acl_requires_review`, or
`state_acl_unavailable`. Missing parent state is an error, not auto-provisioning.
No implicit permission repair or queue reset occurs. Read-only historical output
remains unverified; see [the exact custody scope](STATE_CUSTODY.md).

## Pending admission warning (5.12.1)

Invocations: `collect`, `notify show`, `alerts-forward`. Existing privilege and
locking preconditions apply. After a pending-capacity refusal has been recorded,
these commands print:

```text
WARNING alert_admission_incomplete=yes; notification_history_may_be_incomplete=yes
```

The warning persists after queue recovery and on later successful invocations,
including an empty forwarding backlog or first-run cursor initialisation.
`collect` still writes its normal current-sample result; `alerts-forward` still
reports `remaining` and `evicted_uncheckpointed_total`. Historical warning alone
does not change exit status or send a message. Automation must inspect the warning
as well as monitor nonzero collector/forwarder exits.

Capacity refusals atomically add the boolean to existing `alert-state.json`;
old pending events are preserved and no new queue entry is created. No automatic
acknowledgement/reset is introduced. A malformed state/flag or unavailable write
remains an error. Missing alerts are not fabricated from history; this output
signals possible incomplete notification history, not an exact loss count or
proof of delivery. Concurrent old writers can discard the new field: upgrade
writers together and retain state before rollback.

## Attached worker failure (5.12.1)

Sandboxed Research, Atlas and remote commands retain their existing invocation,
roles and admission checks. If `systemd-run` returns nonzero or dies by signal,
the live parent now requests a stop of that command's exact transient unit and
reaps the launcher before leaving the broker/lock scope. The original failure
status remains nonzero; current successful output is unchanged. Each stop and
subsequent launcher wait remains bounded by the existing 30-second timeout.

This does not undo data committed before cancellation. With an available service
manager, the tested early-launcher-failure case no longer permits the old capture
to publish after a new invocation. Parent SIGKILL and failed/unavailable manager
cleanup remain separate limits: neither a returned CLI error nor a released
console lock proves all role workers have stopped. See
[worker lifecycle scope](WORKER_IDENTITY.md#unsuccessful-launcher-exit-unreleased).

## Configured TCP peer evidence

`check`, mode status and an unchanged `mode direct|tunnel` request now refuse
contradictory established TCP connections to configured TCP/TLS/WS/WSS peers.
Each such socket must have original-direction ESTABLISHED conntrack evidence;
reply-only tuples and stale TIME_WAIT records cannot supply that evidence.
`underlay_peer_socket_proof_missing` means a record or exactly one explicit mark is absent;
`underlay_peer_mark_mismatch` means at least one matching record contradicts the
mode. Direct expects3905; tunnel preserves mark !=3905. A valid sibling flow
cannot override either failure. The success result/output shape is unchanged.

Scope is configured peer destinations owned by the two service PIDs. Local SOCKS
clients, listening sockets, unrelated destinations and other processes are not
expanded into a new all-traffic policy. The pre-existing minimum of runtime
proof for each PID remains. This additional check does not claim complete route,
VPN leak, crypto or network-history validation. Kernel/API observations are not
an atomic snapshot; transient absence may require a retry after convergence.

For example, changing a rule that marks new connections leaves old conntrack
marks intact. A peer reconnect can then create a contradictory new connection.
The unchanged-mode command now fails instead of printing runtime proof verified.
If this happens during compensation or `recover-transaction --apply`, the
existing journal is retained. Restore the intended policy/runtime evidence and
retry recovery; do not delete the journal to bypass proof. No automatic network
repair, new journal format or installation change is introduced. The changed
checks.py hash needs review in the external deployment integrity manifest.
