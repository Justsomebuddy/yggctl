# Worker identity — source 5.8.0 (#7)

The parent chooses the role and random transient unit name. `SO_PEERCRED`
provides the client PID/UID; the parent reads that PID's bounded kernel
`/proc/PID/cgroup` and requires BOTH the selected role UID and the exact
`/system.slice/yggctl-sandbox-ROLE-ID.service` unified cgroup. A request's role,
PID or unit string is never authority. Hybrid hosts may expose v1 controllers;
only the unique unified-hierarchy row is used. Missing/unreadable/ambiguous
identity fails closed. A rejected connection does not consume the one admitted
connection slot. Closing the broker also shuts down an idle admitted socket.

External provisioning must create **three distinct non-root UID/GID principals**:
`ygglab-research`, `ygglab-atlas`, `ygglab-remote`, with no login/password.
Units explicitly use `Slice=system.slice`, `Delegate=no` and the existing
capability, namespace, cgroup and filesystem restrictions. Provision compatible
Linux cgroup-v2/systemd support; a cgroup-v1-only host is unsupported, not an
invitation to disable authentication. Research/atlas stores must be privately
owned by the corresponding role; remote has no persistent store.

This is **role separation plus launch-specific broker admission**, not full
per-launch data or compromised-worker isolation. Every instance of a given role
still shares that role's UID and persistent store. Same-role signalling/process
access, descriptor sharing and denial-of-service remain relevant. Do not claim
that `ProtectProc=invisible` separates processes of one UID, or that endpoint
binding provides a general sandbox-escape proof. Root/systemd and the host's
cgroup custody are trusted. Normal/interrupt worker management remains the
existing attached runner; this change does not implement the proposed separate
root-owner-unit/socketpair lifecycle architecture or guarantee cleanup after
arbitrary root-parent SIGKILL.

### Unsuccessful launcher exit (unreleased)

`systemd-run` is the attached launcher, not the worker service itself. A signal
or unsuccessful launcher exit can leave the unit running even while its parent
is still able to clean up. The attached runner now requests `systemctl stop`
for that unit before returning any nonzero launcher status. It uses the same
bounded stop/reap path as interruption; the original status is preserved.
Successful launcher completion does not add a stop call. Stop-client I/O errors
and timeouts are logged by exception class without replacing the original
failure or interruption.

The stop request runs while the parent still owns its broker and launch/console
locks. This closes the reproduced early-launcher-exit path when the service
manager is available. It is not a new per-launch storage boundary or a proof
that every stop request succeeds. If the parent is killed or the manager cannot
stop the unit, a worker may still finish local work and write its role's store;
an error return must not be treated as evidence of quiescence for migration or
repair. Inspect and stop the exact surviving units before such operations.

A shared worker-lifetime `.worker.lock` is acquired BEFORE the console lock;
an exclusive migration barrier uses that same order. Normal workers of different
roles remain concurrent. Migration waits finitely rather than racing a fresh
worker launch. Older root parents/workers must be quiescent before ownership
migration; old implementations cannot honor a new barrier.

An installation needs a separately reviewed ownership migration, quiescent
workers, byte/mode-preserving ownership rollback and manifest update. Do not
install this source over the old shared-account runtime without that migration.
The public repository deliberately contains no provisioner or installer.
