# Changelog

## [Unreleased]

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

The source version is 5.7.5; this source repository does not change installed files or running nodes.
No stable release, generic installer or live deployment is claimed.
