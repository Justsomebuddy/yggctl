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

Worker roles share one OS identity. Broker UID authentication does not establish
per-worker-instance or mutually compromised-worker isolation; see the explicit
[trust contract](docs/SECURITY.md#worker-trust-principal-source-578-issue-7).

Structural backup preview accepts at most 4 MiB compressed, **8 MiB in total
decompressed TAR bytes**, and 1 MiB per regular member. The aggregate limit is
applied before TAR/PAX/GNU parsing and includes metadata, padding, concatenated
gzip streams and trailing data. An over-budget input fails with
`backup_expansion_limit`; corrupted/truncated gzip is rejected. This is an input
byte budget, not a promised whole-process RSS/CPU limit or archive authentication.
Previously created oversized archives may now be refused; `--apply` stays disabled.
