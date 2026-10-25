# Changelog

## [Unreleased]

- Do not compare stored-history trends for a sanitized peer label that covers
  more than one link. Two WebSocket paths at one endpoint (or an option the
  sanitizer drops) render to one label, and the trend previously fused their
  rows in sample order: two links with constant but different latencies were
  reported as one `rtt_ms` series with a `degrading` verdict. `trend` now
  reports `ambiguous_labels` and `ambiguous_peer_samples`, marks that label's
  availability and RTT as `not_comparable` with `ambiguous_peer_label`, and adds
  the fixed `ambiguous_peer_labels` reason, so the aggregate is
  `insufficient_history` instead of a fabricated drift. Other labels are
  compared as before. Counts, queue IDs, payloads, cursors and stored history
  are unchanged. See [the trend contract](docs/UI_MAP.md#stored-history-trend-5110).

## [5.12.1] - 2026-10-25

- Preserve a bounded admission-warning flag when the producer outbox refuses
  new peer or health events at its capacity limit. Show the warning in `collect`,
  `notify show` and `alerts-forward` after recovery, even with an empty backlog
  and no queue evictions. Preserve existing events and limits; this flag is not
  a count of unique lost messages and does not reconstruct missing history.

- Request transient-unit cleanup when an attached launcher exits unsuccessfully,
  including signal termination, before releasing the parent broker and locks.
  Preserve the launcher status and existing bounded stop/reap behavior. A dead
  parent or unavailable service manager still cannot guarantee worker cleanup.

### Outbound QUIC runtime evidence

- Correlate owned UDP sockets with a unique original-direction IPv4 conntrack
  tuple and an active configured QUIC peer with the expected key. Include
  unconnected UDP sockets in `ss` observations; reject unmatched, shared or
  ambiguous sockets and contradictory mode marks, even beside valid TCP.
- Admit only these proven outbound QUIC sockets alongside the existing loopback
  SOCKS listener. Keep rejection of additional TCP and unproven UDP listeners.
  This is sampled diagnostic evidence, not a VPN routing or packet-history proof.
  See [QUIC operator behavior](docs/UI_MAP.md#outbound-quic-runtime-evidence).

### Configured TCP peer evidence

- Refuse runtime proof when an established socket to a configured TCP/TLS/WS/WSS
  peer lacks original-direction conntrack evidence or has a mark contradicting
  the current mode. A good sibling connection no longer hides the contradiction.
- Retain the transaction journal after failed compensation/recovery proof; a
  successful retry after evidence is repaired archives it through the existing
  recovery path. No schema, route, firewall, delivery or deployment changes.
  See [TCP proof operator behavior](docs/UI_MAP.md#configured-tcp-peer-evidence).

- Reject multiple mark tokens as missing/ambiguous socket evidence; log stop-client
  start and return status without replacing the failed launcher status.

## [5.12.0] - 2026-10-24

- Treat duplicate public peer labels as ambiguous observations for alert tracking.
  Different WebSocket paths at one endpoint can share a redacted label: preserve
  their prior tracking and pending events instead of emitting false recovery or
  reconnect alerts. Other peers continue normally. `collect` records the fixed
  `ambiguous_peer_labels` diagnostic and returns degraded status; private URI
  paths remain omitted. Existing queue IDs, payloads and cursors are unchanged.
- Persist hourly health alerts in the bounded producer outbox before queue writes.
  A transient node/API failure followed by a queue-write error can now replay its
  original alert after a healthy collector restart. Keep its ID, timestamp and
  errors through queue acknowledgement failures; suppress same-hour duplicates
  across pending and queued events. Native sender confirmation and ambiguous-send
  handling are unchanged; local recording still does not prove remote delivery.

- Publish new Atlas JSON/Markdown/DOT/HTML reports as one complete private
  directory. Prepare all formats in a reserved staging directory before an
  atomic directory rename; failed writes do not publish partial generations.
  The next locked report validates and discards only unpublished staging work.
  Preserve legacy flat reports and completed bundles, including their retention
  limit. Returned file paths now point into `atlas-<id>/report.<format>`; consumers
  must use those paths instead of assuming a flat directory layout.
  See the [bundle publication contract](docs/UI_MAP.md#atlas-bundle-publication).

- Recover interrupted Atlas exports on the next `atlas report`: validate the
  bounded export directory before removing only private, single-link temporary
  files matching the console's reserved atomic-write pattern. Preserve completed
  reports and reject unknown or unsafe entries. Hold a separate directory lock
  through validation, recovery and publication; overlapping reports fail with
  `atlas_export_busy` and can retry after the active report finishes. Atlas
  acquisition and the metrics collector retain their independent locks.
  See the [report recovery contract](docs/UI_MAP.md#atlas-export-recovery).

- Refuse unsafe pre-existing privileged state: validate its directory ancestry,
  root ownership, modes, single-link regular protected files and extended ACLs
  before a root lock and after acquisition; the config/key health gate repeats
  admission. Never chmod/chown or repair data implicitly. See
  [state custody](docs/STATE_CUSTODY.md) and [5.12.0](docs/RELEASE-5.12.0.md).

## [5.11.1] - 2026-10-23

- Keep successful `trend [hours] json` stdout to one parseable JSON document by
  moving its `[done]` run summary to stderr. Text trend and other commands retain
  their stdout summary; failed trends retain their existing stderr failure output.
- Separate `events [hours]` lookback (1..72, default 6) from its record limit.
  Show up to 1000 newest matching events, with window/limit/returned/truncated
  metadata and an explicit stderr warning when older matching events are omitted.
  Probe at most 1001 records to distinguish a full result from truncation;
  existing command byte/time bounds and journal redaction remain in force.
  `logs [N]` keeps its existing line-count contract.

- Add independent stream/trace/failure and event ordering/redaction/resource-bound
  regressions; clarify historical external SimpleX provisioning without reviving
  the superseded shared-wrapper sender. See [qualification](docs/RELEASE-5.11.1.md).

## [5.11.0] - 2026-10-22

- Add read-only `trend [hours] [json]` over bounded stored metrics (#42/#43).
  Compare equal sample-count halves (drop an odd middle row), not elapsed-time
  halves, with median/MAD policy thresholds for node counts, error share and
  per-endpoint conditional availability/router-response RTT EWMA.
- Expose present/answered/absent/invalid-state counts, strict projected boolean
  states and observation gaps; do not infer raw-key identity or absent-is-down.
  Count distinct timestamps for the minimum evidence requirement. Future samples,
  stale/short/sparse evidence, malformed peer containers and no comparable
  observed metric cannot produce an aggregate healthy-looking verdict.
- Validate huge integers/nonfinite values safely; overflowed arithmetic is
  explicitly `not_comparable`, never a nonfinite JSON value or silent clamp.
  Batch-local rejection counts preserve diagnostic logging without per-value
  event flooding or global trace switches. Keep zero RTT observations.
- Generate visible JSON/text warnings: history is role-writable, unverified and
  unauthenticated; no origin, immutability, API-truth or live-health guarantee.
  Document privacy-label collisions, count-weighted heuristics and strict CLI
  argument order. Existing deployment/migration boundaries remain unchanged.
- See [scope and qualification](docs/RELEASE-5.11.0.md). Supplied network-stand
  and timing claims are not independently verified source evidence.

## [5.10.0] - 2026-10-22

- Compose #13/#14/#39: preserve fresh observations after replay failure,
  acknowledge pending only from the final synced queue, and persist cumulative
  uncheckpointed-eviction occurrences. Retain up to the ordinary-alert count
  limit **plus one** bounded metadata record under the unchanged 32 MiB cap.
  Upgrade reader/writer together; neither visibility nor local native recording
  guarantees delivery, exactly-once processing or human ACK.
- Recover safe abandoned Research atomic temporaries with writer-owned directory
  locking (#15); log the real context lifetime and failures, not generator creation.
  Completed files are retained; report JSON/Markdown are individually atomic,
  not a joint transaction or power-loss guarantee.
- Label Research capture/map/diff/report, JSON/Markdown/DOT with generated
  unverified role-writable snapshot provenance (#16). No authentication,
  immutability, signature, truthful-API or hostile-same-role isolation guarantee.
- Preserve keyless/multilink peer rows (#18/#17), retaining duplicate rejection
  for tree/paths. Peer diffs account for tuple multiplicity rather than treating
  arbitrary duplicate-row order as a stable per-link identity.
- Require exact unified `/system.slice` sandbox unit paths (#24/#19), stream
  bounded ZIP member data before aggregation (#25/#20), sanitize supported peer
  URI strings including journal-facing text (#27/#22), and reject non-finite
  or unrepresentably large peer counters with controlled failure (#28/#23),
  including integers that overflow `math.isfinite` conversion. No archive
  authentication or legacy-data purge.
- Centralize raw identity checks across gates, samples, alerts, waits, watch
  and peer ranking (#26/#33/#21/#30/#37). `peers-score` exposes `identified`;
  transport `up` alone is not peer/application liveness. Historical projected
  metric booleans retain their distinct schema contract.
- Index stats windows while preserving first-duplicate/absence/output semantics
  (#32/#29); this is not a strict whole-algorithm linear-time claim. Ignore the
  regenerable `.hypothesis/` cache (#34/#31).
- Require collector trigger evidence, accepted oneshot status and a nonempty
  regular metrics file with age 0..900 seconds (#38/#36). Strictly reject any
  future mtime as `collector_data_future_timestamp`; metadata freshness is not
  validation/authentication of every sample.
- Require restored-underlay proof after compensation and explicit transaction
  recovery (#35). Failed proof retains the active journal; the initiating error
  remains primary with compensation/proof failure as its cause. No live-leak claim.
- Keep the 14 original contribution histories and add necessary integration
  follow-ups. Align the 23 common Python source files byte-for-byte with the
  maintained deployment projection; deployment-only legacy tests/provisioning
  remain separate. This repository remains reference source without an installer.
- Deployment safety rule: coordinate reader/writer migration and quiesce only the
  Ygg-specific alert trigger/forwarder, not shared SimpleX. The reviewed external
  hook refuses automatic post-publication 5.10→5.9 downgrade even with a currently
  marker-free queue; retain reached bytes/manifests/queue/cursor/preimages for separately
  reviewed quiesced recovery, not an automatic rollback-success claim.
  Partial publication may leave mixed bytes; keep affected workers stopped until coherent repair.

Exact final evidence and integration commit: [release record](docs/RELEASE-5.10.0.md).
Publication does not modify installed files, services, policy or alert profiles.

## Earlier source history

### Source 5.9.0 — durable native handoff (#9)

- Ygg-only native outgoing-item proof and fsynced pre-launch attempt journal;
  stable event/text/profile binding and intent/receipt/cursor crash recovery.
- Process rc0 is never cursor authority; ambiguous absence stays pending
  without blind resend. No exactly-once/remote delivery/human ACK claim.
- Private configuration, qualified existing ordinary-SQLite profile/schema,
  trusted binary and all-writer shared lock are required external integration.
  Shared bridge/other chains and installed runtimes are unchanged by publication.
- Native SQLite/lock/concurrency, kernel child-death and composed failure tests;
  seven flow-only cases moved to a focused supplemental module, not dropped.

### Source 5.8.0 — worker identity (#7)

- Separate non-root role principals and kernel SO_PEERCRED UID/PID bound to
  the parent-selected unified systemd cgroup; reject foreign clients before
  requests and close idle broker sockets on shutdown.
- Shared worker-lifetime/exclusive migration barrier prevents ownership races;
  normal roles remain concurrent. Same-role stores/principal remain shared.
- External provisioning/ownership migration is required; this is not an
  installer or arbitrary-parent-death/compromised-worker isolation guarantee.
- Cgroup, custody, contention and native-credential regression contracts;
  matching integration/security/UI documentation, unchanged strict QA gates.

### Source 5.7.9 — history writer and bridge contract

- Fix #10: pre-write atomic byte/count bounded suffix compaction; history-write
  failure no longer prevents pending replay or observed/unknown peer-state work.
  Errors remain nonzero; no fabricated samples, corruption reset or history purge.
- Answer #9: publish the inspected credential-free SimpleX CLI bridge algorithm,
  version/mode and actual loss/duplicate windows. Make the process-only rc0 CLI
  disclaimer explicit. No new sender backend, native acceptance or delivery claim.
- Add synthetic byte-cap, write-failure, outage/gap/pending and sender-boundary
  regressions. Runtime/profile/system installation is not part of this source change.


### Source 5.7.8 — observations, archive budget and trust clarification

- Fix #6: unknown node observation retains tracking; do not count missing time
  as uninterrupted downtime. Preserve alerted episodes/recovery and outbox retry.
- Fix #8: cap the entire decompressed TAR at8MiB before metadata parsing, including
  concatenated gzip/padding/trailing bytes. Keep4MiB compressed/1MiB member bounds.
- Clarify #7: workers share one UID trust principal; no per-instance or mutually
  compromised-worker isolation is implemented. Same-UID/order tests are offline only.
- Add synthetic collect/state/queue/recovery, PAX/GNU, corruption and exact-budget
  controls. No live/systemd exploit or runtime deployment qualification is claimed.


### Fixed

- Protect peer telemetry and sender/display output from credential-bearing URI
  metadata (#5). Keep only literal endpoints or established typed public pin/
  timing labels. Legacy queue rendering is protected without rewriting history
  or delivery IDs; unsafe private pending refuses copying into the readable queue.
- Disable unauthenticated `restore --apply` before reads/decryption/locking. The
  read-only structural preview now says NOT AUTHENTICATED, not VERIFIED. A sidecar
  plus internal member hashes proves consistency, not archive origin; no automatic
  integrity promotion or restart remains on this path. Independent authentication
  and separate integrity acceptance are still required before re-enabling apply.
- Add actual synthetic collect/persistence/sender, self-consistent forged archive
  and consumer-derived role regressions. No live-node or historical-data mutation.

- Scope broker admin methods by the parent-selected role (#5, #4): research
  stays local-only, Atlas retains exactly its three remote debug reads, and
  remote commands retain the existing read-only method set. Requests cannot
  select their own role; unknown roles and malformed arguments fail closed.
- Verify integrity under the console lock before starting every sandboxed
  command. An integrity failure starts neither the broker nor the worker.
- Add an offline real Unix-socket Atlas crawl regression, the full role matrix,
  and all-command integrity success/failure ordering tests. No host networking,
  node configuration or sandbox properties are broadened.

- Scope the broker's admin allowlist by sandbox role. `research` keeps local
  reads but can no longer ask the parent to query other nodes, which is what
  `PrivateNetwork=yes` on the research unit already implies. `atlas` keeps the
  remote methods its crawl needs, and `remote` is unchanged.
- Report what the parent actually verified instead of asserting it. The integrity
  check now runs for every sandboxed role before the unit starts, so the claim the
  worker relies on is true for commands that previously skipped it (`ping`,
  `nodeinfo`, `whois`, `debug-remote`, `survey`, `traceroute`). The sockets check
  keeps its existing scope, which matches the single command that reads it.
- Add role-allowlist and per-role integrity regressions; no live deployment
  behaviour is claimed by these tests.

- Keep historical reports available across the collector's complete 10,000–12,000
  record retention cycle (#2). The bounded reader now accepts the pre-compaction
  window; the existing 10,000-record retained tail and other validation remain.
- Size the metrics-only broker reply limit for the full 32 MiB raw file after
  Base64 encoding and the JSON/newline envelope (#3). Admin replies retain their
  existing 24 MiB bound. No data is truncated to satisfy the transport limit.
- Add actual collector/report boundary and local Unix-socket regressions,
  including a full 32 MiB transfer and rejection above the supported caps.

- Preserve peer-down, recovery and instability alerts when queue writing fails
  after the peer transition is saved (#1). The transition and pending event now
  share one atomic state update. Later collections replay stable event IDs,
  including after interrupted writes, partial batches or acknowledgement failure.
- Sync the queue and its directory before retiring pending events, including
  records found during replay. Reject corrupt outbox state instead of discarding
  it. Notifications disabled by the operator retain already-pending events.
- Add synthetic fault/restart/concurrent-collector regressions. This recovers
  queue publication, not exactly-once external delivery or a human acknowledgement.

### Added

- Console-only source repository, MIT license, contributor guidance, security
  policy and documentation of external integration requirements.
- Commit-pinned, read-only Python regression CI with bounded job duration.
- Reproducible Ruff/Mypy/Pytest/coverage configuration and QA-only tool pins.
- Negative origin-port and fail-closed shared-helper integrity regressions.
- Modular adversarial and property tests: 243 unique cases, 1000 Hypothesis
  examples, exact 100% production statements/branches without new exclusions.
- Local bounded numeric mutation, symbolic and seeded parser fuzz checks;
  their limited scope and native ABI boundaries are documented.

### Changed

- Console source is grouped under `yggctl/`; the Go decoder and deployment
  material are intentionally not included, including in reachable history.
- Offline fixture paths no longer depend on the original checkout location;
  broker tests handle long Linux temporary paths.

### Source cleanup (5.7.2 → 5.7.3, unreleased)

- Format Python source consistently, remove unused imports and annotate the
  verified-parent set without relaxing validation or typing rules.
- Preserve origin-port parsing side effects that reject malformed/range errors.
- Check unannotated function bodies with Mypy; type heterogeneous JSON
  boundaries and process streams without blanket diagnostic suppression.
- Retain strict IPv4 parsing while removing unreachable redundant comparisons;
  explicitly reject zero ports through the existing range validation.
- Normalize Unicode/non-decimal and overlong numeric conversion failures to
  the safe CLI error contract; add red/green adversarial regressions.
- Expand CI from stdlib smoke tests to lint/types/security/regressions and an
  exact 100% statement/branch gate; no deployment or remote change.
- Extract logged shared fixtures and prevent duplicate inherited Pytest cases.
- Require `test_support.py` in root integrity coverage because it is imported
  by regression suites. External provisioners must review/update their exact
  manifest before deploying this source; this repository does not do so.
- Explain narrow reviewed Bandit exceptions; retain actual coverage and missing
  broad-SAST limitations rather than advertising a full security pass.
- Document GitHub Issues and pull requests as the contribution/reporting route,
  with synthetic reproducers and no disclosure of operational secrets.

Source publication does not change installed files or running nodes; verify installed versions independently.
No stable release, generic installer or live deployment is claimed.
