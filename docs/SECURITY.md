# Operational limitations

This console assumes a specific deployment. Its privileged commands can stop
services and change configuration. Review paths, identities, permissions,
firewall rules, dependencies and rollback before any isolated operational test.
The repository intentionally provides no installer or host policy.

* Broker permissions are selected by the parent, not by request data. Research
  can read only local admin methods and metrics. Atlas can additionally issue
  `debug_remotegetself`, `debug_remotegetpeers` and `debug_remotegettree`;
  only the remote role can additionally request `getnodeinfo`. All workers
  start after a locked parent integrity check; failure prevents launch.
* Broker restrictions depend on socket ownership/mode, directory permissions,
  systemd confinement and surrounding configuration. Offline tests of a local
  socket do not prove a deployed root/worker boundary.
* Fixed executable paths are deliberate. Generic configuration and safe
  first-time provisioning are not implemented by this reference.
* SimpleX is external. Sender exit zero proves only handoff, not message
  delivery or acknowledgement by a human.
* A `PathChanged`-based external alert trigger has a known race: an alert added
  while the forwarder is running can wait for the next file change. No
  at-least-once delivery guarantee is claimed.
* Offline suites do not verify network mutation, policy acceptance, key custody,
  disaster recovery, or all behavior of privileged commands.
* Configuration input and decoded output can contain sensitive values. Do not
  paste real configuration or decoder output into issues, logs or examples.

For sensitive reports, see the root [security policy](../SECURITY.md).

## Worker trust principal (source 5.7.8, issue #7)

All worker roles run as the same `ygglab-worker` UID. The broker authenticates
that shared UID using kernel `SO_PEERCRED`; it does **not** bind a client PID,
cgroup or systemd unit to one broker instance. A separate same-UID process can
be the first accepted client if it can reach the socket. The broker serves only
one accepted connection, so a second connection cannot replace that client.

Role allowlists restrict calls reaching a particular parent-selected broker;
they are **not mutual security isolation between compromised workers**. Socket
mode/ownership and the common UID do not distinguish those workers.
`ProtectProc=invisible` hides other users' processes, not processes of the same
UID. The role-specific filesystem/network restrictions still matter, but do not
establish a new identity for broker authentication. Do not use this reference
as a boundary between independently untrusted worker roles or instances.

A stronger deployment needs independently separated principals and a reviewed
per-instance endpoint/client authentication design, including descriptor sharing,
process access and lifecycle handling. Merely comparing a request-supplied role,
PID or token is not that design. Such strengthening is **not implemented** here.
The offline same-UID and connection-order tests are contract witnesses, not a
full-systemd exploit, sandbox-escape test or proof of deployment isolation.

## SimpleX process success is not message acceptance (5.7.9; #9)

The inspected external bridge discards one-shot CLI stdout and checks only
process status. A handled command error can be checkpointed; acceptance followed
by timeout can be retried and duplicated. Rate suppression is not stable native
idempotency. [Full credential-free algorithm, version/mode and limits](SIMPLEX_BRIDGE.md).
No new native sender, transport guarantee or human-ACK observation is claimed.
