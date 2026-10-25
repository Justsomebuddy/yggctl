# Source 5.12.1: admission warnings, worker cleanup and underlay evidence

This patch release preserves the original histories of #53, #54, #55 and #56.
It does not include the separate privacy, throughput or overlay-policy feature
proposals. No installer, dependency or node change is bundled.

## Behavior

* Pending-capacity refusal durably marks `alert-state.json` with the bounded
  boolean `admission_incomplete` when that file remains writable. Subsequent
  `collect`, `notify show` and `alerts-forward` warn about possibly incomplete
  notification history even after the backlog empties. Existing events and
  limits remain unchanged. The flag is neither a unique loss count nor a
  reconstruction of refused events; complete storage failure cannot persist it.
  Warning alone does not make a currently successful command fail or send an
  alert. There is no automatic clearing or acknowledgement.
* An attached launcher returning nonzero, including a signal status, requests
  stop of its exact transient worker unit before the live parent releases its
  broker/locks. Preserve the launcher status; log the stop-client result. The
  existing stop/reap timeouts remain. Parent death, manager failure and already
  committed observations remain outside a guaranteed-cleanup/undo claim.
* Outbound configured QUIC links may supply sampled runtime evidence by joining
  an owned UDP port, one original-direction IPv4 conntrack tuple and an active
  outbound peer with its configured key. Ambiguous/shared/unmatched UDP refuses,
  even beside valid TCP. The listener gate admits only proven outbound QUIC plus
  the existing loopback SOCKS listener; no arbitrary new listener is allowed.
* Every observed established socket to a configured TCP/TLS/WS/WSS peer must have
  original-direction ESTABLISHED evidence and an unambiguous explicit mark.
  A good sibling no longer hides missing or contradictory evidence. Direct
  expects mark3905; tunnel preserves the predicate mark!=3905, not strictly0.
  Reply-only tuples, TIME_WAIT and multiple mark tokens do not satisfy this check.
  Failed compensation/recovery retains its existing transaction journal until
  verified recovery. Local SOCKS clients and unrelated destinations remain
  outside this additional configured-peer check.

These are sequential observations, not atomic kernel state, packet-route
attestation, a historical completeness proof or an anonymity/VPN-leak guarantee.
Transient churn, stale conntrack and port reuse can require retry after convergence.
No firewall, mode, peer, key, sender, cursor or queue reset is introduced.

## Compatibility and qualification

Older writers may discard `admission_incomplete`; quiesce writers together and
preserve state before any reviewed downgrade. Existing pending/Atlas format
[recovery barriers](RELEASE-5.12.0.md) still apply. Partial publication must retain
reached/mixed bytes and stop affected workers until coherent repair. Preimages
are not permission for automatic old-reader rollback. Review changed runtime
hashes in an external deployment manifest before installation.

The local composed source passed **555 tests**, all nine configured gates,
**4578/4578 production statements and 1690/1690 branches**, zero exclusions.
The separate console/research/Atlas suites and original-base behavior controls
are independently recorded during release qualification. Existing QA tools are
reused offline; no package/interpreter is installed. Finite synthetic results
are not a deployment qualification or proof of real SimpleX delivery/human ACK.
Check Actions for the exact published commit, not a constituent PR's old run.
See [interaction details](UI_MAP.md) and [verification scope](VERIFICATION.md).
