# Security policy

## Supported scope

This is experimental reference source. There is no supported stable release or
security-update SLA. Testing the source does not qualify a host deployment.
See [operational limitations](docs/SECURITY.md) before running commands.

## Reporting

Report bugs and security concerns through
[GitHub Issues](https://github.com/Justsomebuddy/yggctl/issues). Include the
affected commit, expected and actual behavior, and a minimal synthetic
reproducer. Propose fixes through a focused pull request from a fork or topic
branch; contributing does not grant direct push access to the default branch.

Public reports, patches and CI logs must not contain credentials, private keys,
live configuration, real node identities, raw operational logs or databases.
Replace sensitive inputs with synthetic examples before posting. If GitHub
offers a private report option in the repository's Security tab, it may also be
used; this policy does not claim that option is enabled. No separate external
reporting channel or response-time guarantee is advertised.

## Backup origin and peer URI output

`restore` currently supports structural preview only. A matching `.sha256` and
internal manifest are corruption checks, **not origin authentication**. `--apply`
is disabled until independent archive authentication and separate integrity
acceptance are reviewed; encrypted archives alone do not solve this trust issue.

New telemetry and peer-alert output remove unapproved URI metadata. Only typed
public pin/timing parameters may survive. This does not erase previously stored
or transmitted data. Legacy private pending with unsafe URI metadata is retained
and refuses copying into the readable queue; review/remediation is separate from
normal delivery and must preserve stable IDs and acknowledgement state.

## Worker identity and archive resource limits

Roles use distinct provisioned OS identities plus kernel UID/PID and expected
unit admission. Instances of one role still share their principal and store;
there is no per-launch historical-data isolation or general mutually compromised
worker guarantee. Exact unified `/system.slice` matching is necessary cgroup
recognition, not a replacement for broker admission. See the explicit
[trust contract](docs/SECURITY.md#worker-principals-580-7).

Structural backup preview accepts at most 4 MiB compressed, **8 MiB in total
decompressed TAR bytes**, and 1 MiB per regular member. The aggregate limit is
applied before TAR/PAX/GNU parsing and includes metadata, padding, concatenated
gzip streams and trailing data. An over-budget input fails with
`backup_expansion_limit`; corrupted/truncated gzip is rejected. This is an input
byte budget, not a promised whole-process RSS/CPU limit or archive authentication.
Previously created oversized archives may now be refused; `--apply` stays disabled.

Atlas repository ZIP parsing also streams member data with bounded reads and an
8 MiB aggregate library-delivered-byte budget. This does not independently attest
all hidden compressed-stream bytes, bound whole-process RSS or authenticate an
archive. A crafted-response test is not evidence of a remote-peer exploit or
TLS verification bypass.

## Source 5.10.0 trust and recovery boundaries

Research capture/map/diff/report outputs visibly declare
`unverified_role_writable_history`, `authenticated=false` and
`immutable_since_capture=false`. The reader constructs the warning; it is not
accepted from a stored snapshot. Schema validation, `sources=ok` and
`identity_stable=true` do not verify origin, unchanged history or API truth.
A store owner can fabricate structurally valid history. No signatures, separate
attestation principal or authenticity/immutability guarantee is implemented.

Writer-owned directory locking protects cooperative Research writers and orphan
temporaries during actual writes/scans. It is not hostile-same-role isolation,
whole-run serialization or a transaction across report JSON and Markdown.

Rollback and explicit transaction recovery require the restored mode's underlay
proof before clearing/archiving the journal. Failure remains pending and blocks
further transactions. Missing evidence is a fail-closed refusal, not proof of a
real traffic leak. File restoration/journal writes can themselves fail; offline
fault tests are not a power-loss or live policy qualification.

Collector freshness uses timer/service properties and file metadata. Future
mtime is rejected, not tolerated as fresh. Recent metadata does not prove valid
samples or an uncompromised collector. Retention counters expose eviction
occurrences, not unique lost messages, native delivery or human acknowledgement.
