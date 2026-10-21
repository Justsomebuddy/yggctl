# Architecture and external integration

The entry point `yggctl/main.py` dispatches commands through an explicit table.
It is run as a source script; this repository is not a pip distribution.

| Module | Responsibility |
| --- | --- |
| `core.py` | Fixed paths/executables, bounded invocation, shared logging |
| `checks.py` | Deployment-specific health and integrity checks |
| `management.py` | Service controls and peer/config transactions |
| `telemetry.py` | Local metrics, reports and alert handoff |
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
| Monitoring | Existing metrics timer/service and optional external SimpleX sender |
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

### Peer alert persistence

Peer transitions and their pending notification events share one atomic
`alert-state.json` update. Pending records keep their original timestamp and
stable ID. Later collections replay them into `alerts.jsonl`, comparing IDs
and content to avoid re-appending an already queued event. Both the queue file
and its parent directory are synced before pending records are retired.

Legacy state without pending records is accepted. Malformed state/outbox data,
conflicting IDs, more than 1000 pending events or a state larger than 1 MiB fail
closed; existing pending events are not silently discarded. Already-pending
events wait while notifications are disabled. Missing events lost by older
versions cannot be reconstructed automatically.

This covers producer-side queue recovery. Queue retention, consumer wakeups,
external sender behavior and human acknowledgement are separate contracts;
exactly-once delivery is not promised.

### Other commands

Peer/config transactions generally preview unless `--apply` is supplied.
**This is not a global dry-run guarantee.** Service controls and some other
commands have immediate effects. Network commands and atlas acquisition can
initiate traffic. Several legacy operations, including `purge`, `rotate-key`,
`chaos`, `upgrade` and `baseline-update`, are disabled.

Do not run operational commands against a production host to test this tree.
Any integration or deployment requires a separate plan and rollback.

## Source 5.8.0 worker integration

Reviewed separate-role [provisioning/migration](WORKER_IDENTITY.md) is required;
source publication is not installation.
