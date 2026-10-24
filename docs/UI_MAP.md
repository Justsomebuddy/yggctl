# Historical report interaction contract

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
