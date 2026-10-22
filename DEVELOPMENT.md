# Development and repository boundaries

This source tree is a deployment-specific reference. It is not the authority
for any operator's private installation. A repository push must not install or
deploy anything, and a passing CI run does not authorize operational changes.

## Included and excluded scope

Include reviewed Python console source, synthetic regression tests and neutral
documentation. Keep research/atlas code separate from acquired observations.
The Go decoder, node, installer, systemd units and host policy are external;
do not silently vendor them or expand the scope of this repository.

Never commit credentials, keys, real node/user configuration, actual peer
lists, raw logs or alerts, databases, backup archives, policy baselines,
personal filesystem paths, private operational notes or local process records.
Prefer loopback or RFC 5737 examples. Some offline fixtures use known public
resolver addresses only to test global-address validation; tests do not contact
them. `.gitignore` does not remove an already committed object.

Review the complete reachable history, commit messages and metadata, not just
the latest tree. Classify secret-scan findings without printing their values.
If a secret is exposed, treat it as compromised and handle it privately; a
revert is not sufficient. Check provenance and licensing before adding material.

## Safe change process

1. Keep one independently reviewable concern per branch/PR. Use Conventional
   Commit messages and describe the motivation, behavior and test evidence.
2. Add synthetic tests for changed behavior, failures and security boundaries.
   Use the existing secret-safe `@logged` convention for production functions;
   never log credentials, private keys or raw untrusted command output.
3. Run the configured lint/type/security checks and Pytest discovery/coverage
   in [Verification](docs/VERIFICATION.md), plus all three README suites.
   Inspect the diff, new files and documentation
   links. Update the changelog for user-visible changes. No package or Python
   upgrade is part of routine testing.
4. Test operational behavior only in an isolated disposable environment, never
   against an existing node. Check [command effects](docs/ARCHITECTURE.md).
5. Any production integration needs a separate review of dependencies,
   privileges, configuration and manifests, with exact rollback and explicit
   approval from that installation's operator. No automatic sync to an existing
   installation is provided.

### Composed changes and source parity (5.10.0)

Preserve contribution commits and add reviewable owner follow-ups where independent
PRs change one contract. In particular, queue-loss metadata must not silently
consume ordinary pending capacity: test reduced capacity, partial replay, byte
pressure, acknowledgement failure and restart together, not just each patch alone.
An old queue reader/writer cannot safely consume the new marker format.

The reviewed deployment projection and reference tree share 23 Python source
files byte-for-byte. The deployment projection retains a separate legacy
`alert_tests.py` and its own provisioning; neither becomes a bundled public
installer. Check the exact common-file mapping after each change, then test both
layouts. Equal version numbers alone are not source or behavior parity evidence.

Context managers must log their actual enter/yield/exit/error lifetime; decorating
only generator creation is insufficient. Log fixed operation/state labels and
exception classes, never supplied paths, exception text or raw responses.

For every CLI semantic change, update `docs/UI_MAP.md` with invocation,
preconditions, successful/degraded/error output and side effects. Keep raw API
identity consumers distinct from historical projected metric booleans. Provenance
warnings must remain generated and must not upgrade writable history to trusted
history. Qualification and release statements must cite the final exact source
and finite evidence, not a previous PR's green run.

### Integrity manifests and shared fixtures

`test_support.py` is imported by all three regression suites. The console's
root-integrity gate therefore requires it alongside `tests.py` and the runtime
modules. Any external provisioner must include its exact hash in the reviewed
root-owned manifest; omitting it fails closed. Updating this source repository
never updates an installed manifest or authorizes deployment. Keep fixtures
synthetic and logged, and avoid inheriting one test suite from another: Pytest
would otherwise collect inherited cases more than once.

Keep new edge/property tests under `tests/`, grouped by responsibility, rather
than growing the legacy runtime test modules. Production coverage must retain
all reachable statements/branches with meaningful assertions. Do not add
exclusions or weaken validation to satisfy the gate. Property tests use a fixed
profile and no persistent example database. Bounded mutation/fuzz evidence and
its limitations must stay distinct from statement/branch coverage.

## Publication checklist

Private staging does not waive the standards for a later public repository.
Changing visibility, transferring ownership and contacting upstream are separate
decisions, not side effects of merging code or passing tests.

Before a public visibility decision:

* Review every reachable branch/tag/object and all commit metadata; do not push
  mirrors, unrelated refs or raw extraction history. Re-scan the exact payload.
* Record the tested SHA, environment, suite counts, static-check scope and
  checks not run. Verify the actual hosted CI run for that SHA. A locally parsed
  workflow or mocked test is not live-integration evidence.
* Review external prerequisites, supported versions and known limitations.
  Do not promise generic installation or cross-platform support without tests.
* Keep the GitHub Issues/pull-request contribution and reporting workflow
  documented, including the sensitive-data rules in [SECURITY.md](SECURITY.md).
  A separate external reporting channel is not a publication prerequisite.
  Review repository access, Actions permissions and branch-review settings.
  Do not claim that CODEOWNERS alone enforces review or that protections are
  configured by source.
* Confirm the visibility change explicitly with the owner. Maintain this as an
  independent community tool unless upstream explicitly agrees otherwise.

The raw-peer regression guard also inventories direct literal `up` reads in every
maintained runtime function. A new read or consumer requires explicit semantic
classification; the reviewed allowlist distinguishes schema/transport projection
from persisted metric booleans. This AST guard is not complete data-flow analysis
and does not establish application liveness or cover dynamic field aliases.
