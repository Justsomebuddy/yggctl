# Source 5.12.0: alert recovery, complete Atlas exports, state custody

This release composes the original #48 and #51 histories (the latter already
contains #48) with #50 and a bounded response to #49. It does not bundle or
qualify an installer, alter shared senders, install packages or change node,
peer, key, underlay or firewall policy.

## Behavior and compatibility

* Duplicate redacted peer labels are ambiguous, not independent identities.
  Preserve prior tracking and pending events, suppress guessed transitions and
  report degraded observations. Other peers and durable replay continue.
* Stage hourly health intents before queue I/O using the bounded producer
  outbox. Replay retains original IDs/timestamps/errors and existing duplicate,
  retention and acknowledgement checks. Pending now admits health records too:
  do not downgrade to an older pending reader without preserving/reviewing state.
  Capacity exhaustion still refuses new intents; durable storage failure cannot
  be turned into a delivery guarantee.
* Atlas exporters serialize using a nonblocking directory lock. Validate the
  bounded inventory before discarding recognized unpublished work. Build all
  four formats in a private stage and publish a complete bundle by one rename.
  Returned paths now use `atlas/atlas-<id>/report.<format>`; follow returned
  paths, not legacy top-level globs. Existing flat exports are preserved.
  Quiesce old exporters before upgrade; older scanners reject new bundles.
  Preserve/archive new bundles before any reviewed older-reader rollback.
  A failure after publication may leave a complete bundle despite a failed CLI
  result. No exactly-once generation or hardware power-loss guarantee is made.
* Root lock-taking operations and the config/key health gate validate
  [existing state custody](STATE_CUSTODY.md), without silently repairing it.
  ACL inspection requires Linux support; uncertainty refuses rather than passes.

Partial publication must retain reached/mixed bytes and stop affected workers
until coherent repair. Existing [recovery rules](RELEASE-5.10.0.md) still apply;
retained preimages are not permission for automatic old-format downgrade.

## Qualification scope

The composed candidate is checked with the existing nine-stage offline source
gate: syntax, Ruff lint/format, Mypy, both Bandit checks, test discovery, tests
and exact production statement/branch coverage with zero exclusions. The three
README suites remain separate. Added custody tests cover unsafe types, owners,
modes, hardlinks, ACL/default ACL, unavailable inspection, missing state and
pre/post-lock rejection without permission repair.

See [verification commands and limits](VERIFICATION.md) and the
[interaction contract](UI_MAP.md). Source tests and contributor CI do not qualify
the composed installed bytes. Check Actions for the exact published commit's
result. History remains unverified; neither local queue/native recording nor
tests prove remote SimpleX delivery, exactly-once notification or human ACK.

The final local candidate passed **519 tests**, all nine gates,
**4439/4439 production statements and 1616/1616 branches**, zero exclusions.
Separate stdlib suites passed **93/24/33** cases. Four original-base transplants
reproduce the ambiguity, health-intent, partial-export and missing-lock-admission
failures. A root offline namespace exercised real regular files, modes,
hardlinks, symlinks, FIFOs, access/default ACLs and unsafe ancestors. These are
finite candidate results, not a deployed-system or hosted exact-SHA claim.
A deterministic successful kernel-wait contract supplements the existing native
concurrency test so branch coverage does not depend on winning a scheduler race.
