# Historical report interaction contract

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
| IPC-WORKER-PRINCIPAL | Sandboxed command launch | Shared UID authentication only, no per-PID/cgroup/unit binding or mutual compromised-worker isolation; [explicit limitations](SECURITY.md#worker-trust-principal-source-578-issue-7). |

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
`SIMPLEX_BRIDGE.md` (public) / doc35 (private). No new command or network policy.
