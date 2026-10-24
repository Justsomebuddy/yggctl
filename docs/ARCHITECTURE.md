# Architecture and external integration

The entry point `yggctl/main.py` dispatches commands through an explicit table.
It is run as a source script; this repository is not a pip distribution.

| Module | Responsibility |
| --- | --- |
| `core.py` | Fixed paths/executables, bounded invocation, shared logging |
| `checks.py` | Deployment-specific health and integrity checks |
| `management.py` | Service controls and peer/config transactions |
| `telemetry.py` | Local metrics, reports and alert handoff |
| `simplex_sender.py` | Ygg-only durable native-recorded handoff, fail-closed ambiguity |
| `recovery.py` | Deployment-specific backup and recovery operations |
| `sandbox.py`, `broker.py` | Worker launch, mandatory integrity gate and role-scoped admin reads |
| `research/`, `atlas/` | Bounded observed-network collection and analysis |

Observations are not a census of the entire Yggdrasil network. Source code
includes no acquired observations or operating node identities.

## Runtime contract: external, not bundled

| Component | Assumption |
| --- | --- |
| Node and stack | Existing `yggdrasil-lab.service`, `yggstack-lab.service`, binaries and admin Unix sockets |
| Configuration | `/etc/yggdrasil-lab` and `/usr/local/libexec/yggdrasil-lab/config-json` |
| Decoder | Separately provisioned HJSON-to-JSON helper; its source/binary and Go dependencies are not included |
| Runtime/state | Dedicated `/run/yggdrasil-lab` and `/var/lib/yggdrasil-lab` trees |
| Isolation | systemd/cgroup-v2, three role principals, broker under `/run/yggctl-broker`, Linux `/proc` |
| Policy | Independently reviewed firewall/nftables baseline; some checks assume Mullvad |
| Monitoring | Existing metrics timer/service and optional reviewed native SimpleX integration |
| Integrity | A pre-provisioned manifest that also covers files outside this repository |

These integrations are not installed by this repository. An externally
provisioned `rotate.py` is also part of the integrity assumptions; console key
rotation is disabled. Defaults are hard-coded and not environment-overridable.
Removing fixed paths or sandbox settings ad hoc is not a portability solution.

The root parent launches selected roles with `systemd-run` as an unprivileged
worker and mediates allowlisted node reads through a Unix socket. The full
installed ownership, permissions and sandbox must be reviewed independently;
these source files alone are not a complete security boundary.

## Command effects

### Producer alert persistence

Peer transitions and their pending notification events share one atomic
`alert-state.json` update. Pending records keep their original timestamp and
stable ID. Later collections replay them into `alerts.jsonl`, comparing IDs
and content to avoid re-appending an already queued event. Both the queue file
and its parent directory are synced before pending records are retired.

Hourly `ygg-health` events also enter this bounded outbox before queue writes.
Their original errors, timestamp and ID survive a queue failure even if the next
collection is healthy. Hourly suppression checks pending events as well as the
queue. Old pending events drain before new events are staged, so a full outbox
can recover when queue writes become available. Health and peer events share
the existing capacity; neither silently evicts the other's pending records.
Peer observation state is processed before staging new health events, including
after an initial replay failure. A corrupt/unreadable queue still blocks health
hour-key checking; no implicit repair or metrics-history backfill is performed.

Older collectors reject health entries in `pending`. Coordinate writer upgrades;
before rollback, drain pending with the new code or preserve the state for
operator review. Do not delete pending records to make an older writer accept it.

Legacy state without pending records is accepted. Malformed state/outbox data,
conflicting IDs, more than 1000 pending events or a state larger than 1 MiB fail
closed; existing pending events are not silently discarded. Already-pending
events wait while notifications are disabled. Missing events lost by older
versions cannot be reconstructed automatically.

This covers producer-side queue recovery. Queue retention, consumer wakeups,
external sender behavior and human acknowledgement are separate contracts;
exactly-once delivery is not promised.

### Source 5.10.0: composed producer and retention behavior

An initial pending replay still runs before staging new transitions. If replay
fails, the collector attempts to save the already-observed peer transition or
unknown-observation gap, then reports the failure. It does not silently repair
corrupt queues, conflicting IDs or unsafe legacy payloads; bounded state writes
can also fail. After appending missing events, replay revalidates IDs **and full
payloads in the final queue**, then syncs before clearing only retained pending.
Evicted pending remains retryable with `alert_pending_retained_after_queue_rotation`.

The queue can retain `keep` ordinary alerts **plus one** `ygg-queue-retention`
record. All bytes remain within the same 32 MiB bound; metadata reservation can
reduce the ordinary suffix under byte pressure. Its cumulative
`evicted_uncheckpointed_total` counts eviction occurrences lacking a local
checkpoint, not unique undelivered messages. The marker is local metadata:
never handed to SimpleX and never consumes native-attempt capacity. A nonzero
historical total alone does not change exit status; monitor increases separately
from `remaining`. Upgrade the reader and writer together; old code can misread
or discard the marker. Missing historical alerts are not reconstructed.

### Identity, history and freshness are different contracts

Raw API consumers use `checks.identified`: exact `up is True` and a lowercase
64-hex public key. It is shared by peer gates, collection/alerts, waits, watch and
peer ranking. `peers-score` adds `identified` and ranks identified rows first,
then by latency; it is not a trust/reliability/application-liveness score.
Persisted schema-2 `up` booleans are already projected observations, not raw
identity assertions to re-evaluate without a key.

Research preserves all bounded peer rows, including keyless and multilink rows.
Tree/path key duplicates remain invalid. Graphs aggregate direct links; diffs
compare `(key, port, inbound)` group multiplicity and up-link counts, independent
of duplicate-row ordering. Added/removed remain group tokens and `changed` also
includes count changes. There is no stable per-transport-link identity.

Every generated Research map/diff/report and capture result labels snapshots as
unverified role-writable history. Stored schema 1 stays unchanged; file-supplied
trust claims are not admitted. `sources=ok`, stable local keys and schema checks
are not authenticity, unchanged-history or API-truth proofs. Capture declares
`local_api_sequential_unattested`; reports and DOT/Markdown retain the warning.

Research's worker owns a nonblocking directory flock around scans and each
actual atomic artifact write. Only validated, owned mode-0600 single-link regular
temporary files with reserved names are cleanup candidates after a full bounded
directory scan. Unsafe/unknown entries fail closed; completed artifacts remain.
This is cooperative crash recovery, not whole-run serialization or a two-file
JSON/Markdown transaction. No hostile-same-role or power-loss guarantee follows.

The collector gate requires an active timer, nonempty trigger evidence, accepted
oneshot status and a nonempty regular metrics file with age 0..900 seconds.
Any future mtime fails with `collector_data_future_timestamp`; older data fails
with `collector_data_stale`, absent/empty/nonregular data with
`collector_data_missing`, and missing trigger evidence with `collector_never_fired`.
These properties are bounded freshness heuristics, not sample validation or
collector authentication. Timestamp window filters still refuse/omit old samples;
old data is not relabelled as current.

### Compensation and explicit transaction recovery

After restoring preimages and running compensation, `transaction` proves the
restored underlay before deleting its active journal. A compensation/proof failure
retains the journal with `rollback_runtime_failed`; the initiating action error
remains primary and the secondary failure is its cause. Recovery apply restores,
restarts/converges, checks integrity and proves underlay **before** archival.
Failure preserves the active journal for explicit retry and blocks new mutations.
Preview remains read-only and performs neither restart nor underlay probing.
No new journal schema, retry loop, live-leak or power-loss guarantee is introduced.

### Other commands

Peer/config transactions generally preview unless `--apply` is supplied.
**This is not a global dry-run guarantee.** Service controls and some other
commands have immediate effects. Network commands and atlas acquisition can
initiate traffic. Several legacy operations, including `purge`, `rotate-key`,
`chaos`, `upgrade` and `baseline-update`, are disabled.

Do not run operational commands against a production host to test this tree.
Any integration or deployment requires a separate plan and rollback.

## Source 5.9.0 integration changes

Worker identities require the [separate-role migration](WORKER_IDENTITY.md);
alert forwarding requires [private native-handoff configuration and shared-lock
qualification](NATIVE_HANDOFF.md). Neither is an automatic install step.

## Source/deployment projection

The 23 common Python files are reviewed as byte-identical to the maintained
deployment projection. Deployment-only legacy `alert_tests.py`, installation,
manifests, units and configuration remain separate. This reference repository
does not install, migrate or restart either layout. See the
[5.10.0 qualification record](RELEASE-5.10.0.md) for the final source and evidence.
