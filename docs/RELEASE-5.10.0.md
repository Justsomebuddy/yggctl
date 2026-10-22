# Source 5.10.0 — composed recovery and honest trust boundaries

Date: 2026-10-22. This is deployment-specific reference source, **not a bundled
installer or automatic upgrade**. Existing role provisioning, native-handoff
configuration, units, manifests and policies remain external prerequisites.

## Exact qualification

- Qualification target: the composed source 5.10.0 tree. Exact source/merge SHAs
  and hosted checks are recorded independently in the aggregate release PR.
- Finite final test/static-check/coverage evidence: 9/9 local gates PASS; 412 tests PASS; 3969/3969 statements and 1422/1422 branches covered, zero exclusions. Five semantic-reversion controls each fail as intended. These local results are not a hosted-CI or installation claim.

Only that final record establishes the tested source, counts and actual CI state.
A contribution's individual green run does not qualify its composition with other
changes. Initial integration failures were investigated rather than suppressed;
coverage alone does not establish correctness. No source test result proves live
overlay behavior, external delivery, human ACK, power-loss safety or host policy.

## Contributions and necessary integration follow-ups

The 14 original contribution histories are retained. Owner follow-ups reconcile
shared contracts and add missing logging, documentation and regressions.

| PR | Included contract | Important bound / follow-up |
|---|---|---|
| #13 | Stage fresh observation/gap even after initial replay failure | Original failure stays visible; bounded pending/state may still refuse staging. |
| #14 | Revalidate exact pending payloads in final synced queue | Only retained matches acknowledged; later retention is a separate loss window. |
| #15 | Recover validated abandoned Research atomic temporaries | Writer owns flock during actual write; generator lifetime logging added. Not whole-run/pair atomicity. |
| #18 | Preserve all bounded peer rows, including keyless/multilink | Tree/path duplicates still invalid; tuple-multiplicity diff added, without per-link identity. |
| #24 | Exact unified `/system.slice` own-unit recognition | Does not replace UID/PID/expected-unit broker admission. |
| #25 | Stream ZIP member bytes before bounded aggregation | Counts bytes delivered by ZIP reader, not independent hidden-stream/RSS attestation. |
| #26 | Reject transport-only rows in peer gate | Reuses central `identified`, not a second diverging predicate. |
| #27 | Sanitize supported peer URI output and journal-facing text | Keep typed public labels; not a general secret detector or legacy purge. |
| #28 | Reject non-finite/unrepresentably large peer counters with controlled failure | Includes integers overflowing `math.isfinite` conversion; not an alleged external exploit or old-history repair. |
| #32 | Index stats window lookups | Same first-duplicate/absence/output semantics; positions are still scanned per name. |
| #33 | Use identified peers in sampling/alerts/waits | Extended consistently to watch/ranking; historical projected booleans unchanged. |
| #34 | Ignore regenerable `.hypothesis/` cache | No tracked historic-cache or runtime-vulnerability claim. |
| #38 | Require trigger/status/data freshness evidence | Any future mtime now strictly fails as `collector_data_future_timestamp`. |
| #39 | Persist uncheckpointed-eviction occurrence visibility | Ordinary count limit plus one bounded marker; same byte cap; reader/writer upgrade together. |

## Additional accepted fixes and boundaries

**Research trust (#16).** Capture/map/diff/report and JSON/Markdown/DOT expose
generated `unverified_role_writable_history` provenance. Authentication and
immutability flags are false; `sources=ok`, schema validation and a stable local
key do not prove origin, unchanged history or API truth. A store owner can still
fabricate valid observations. There are no signatures or authenticity/immutability
guarantees. Snapshot schema 1 is unchanged; no fake signing or history reset.

**Restored-underlay proof (#35).** Both transaction compensation and explicit
recovery must prove the restored underlay before clearing/archiving the active
journal. Failed compensation/proof retains retryable evidence and blocks new
mutations. The initiating action error remains primary. This fixes the missing
proof boundary; no real traffic leak or deployed-adapter bypass is asserted.

**One raw identity predicate (#37).** Peer gate, collection/alerts, waits, watch
and ranking require boolean transport `up` plus lowercase 64-hex identity.
`peers-score` exposes `identified`, not a trust/reliability score. Persisted
projected metric booleans are not retroactively interpreted as raw API replies.

**Collector false green (#36).** An active timer and never-run inactive oneshot
alone no longer pass. Trigger evidence, accepted service status and recent
nonempty regular-file metadata are required. Age 0..900 seconds is eligible;
any future mtime is refused distinctly. These are freshness heuristics, not
per-sample validation. The claim that last week's records are presented as the
last 24 hours was not reproduced: existing timestamp filters already reject an
empty stats window or return zero Research samples.

## Queue compatibility and remaining loss boundaries

At `keep=1000`, compaction may retain 1000 ordinary alerts **plus one** local
marker, not 999 alerts plus a marker. The same 32 MiB cap covers everything;
metadata byte reservation can reduce the ordinary suffix under byte pressure.
The cumulative counter tracks uncheckpointed eviction occurrences, not unique
undelivered messages. It neither restores lost records nor causes permanent
nonzero exit solely for historical loss; monitor increases separately.

The marker is never sent or entered in native-attempt journals. New reader and
writer must be deployed together: old readers may treat it as an alert and old
compactors may discard it. Durable native local recording is still not delivery,
exactly-once behavior or human acknowledgement. Ambiguous sends remain pending
without blind resend; no accepted history or cursor is silently reset.

### External migration runbook

1. Review role/profile/manifest prerequisites and preserve exact file preimages,
   candidate code/manifest and current queue/cursor. This reference contains no
   installer; a source merge does not perform these steps.
2. Coordinate all queue reader/writer changes. The reviewed external flow
   quiesces the **Ygg-only** alert path/service during migration; shared SimpleX
   remains untouched. An old process with already-imported code is not made safe
   merely by replacing files on disk or observing a marker-free queue once.
3. After 5.10 publication, the deployment hook conservatively **refuses automatic
   5.10→5.9 downgrade**, including when the queue is currently marker-free. This
   closes the old-writer/marker race rather than claiming automatic rollback.
4. On refusal/failure retain candidate, manifest, queue/cursor and exact preimages.
   Require a separately reviewed, quiesced recovery plan before changing format
   readers/writers. Do not clear queues, reset cursors, silently discard markers
   or report rollback success merely because old files are available.

These are migration/refusal rules, not evidence that any live upgrade, delivery
or recovery has happened. Runtime verification belongs in its own finite record.

## Source/deployment separation

All 23 common Python files are byte-identical in the reviewed maintained
deployment projection. Its legacy `alert_tests.py` and deployment machinery
remain separate. This public reference contains no installer, node/decoder,
host units/configuration, operational identities, data or credentials. Publication
does not install, restart, migrate roles/profiles or change network policy.

See [CLI interactions](UI_MAP.md), [architecture](ARCHITECTURE.md),
[security policy](../SECURITY.md) and [development rules](../DEVELOPMENT.md).
