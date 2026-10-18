# Operational limitations

This console assumes a specific deployment. Its privileged commands can stop
services and change configuration. Review paths, identities, permissions,
firewall rules, dependencies and rollback before any isolated operational test.
The repository intentionally provides no installer or host policy.

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
