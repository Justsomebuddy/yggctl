# Source 5.12.2: ambiguity-safe stored-history trends

This patch composes #64 and #65 while retaining both contribution histories.
It does not include the separate privacy, throughput or overlay-policy proposals.
No installer, dependency, interpreter, node or network-policy change is bundled.

## Operator behavior and limits

Two rows can share one public display label without describing one comparable
link: WebSocket paths and unsupported options are omitted, and a row may also be
duplicated. Previously, changing row order could turn two constant latencies
into a fabricated drift. If any observed sample in either compared half has
duplicate labels, `trend` now withholds both availability and RTT comparisons
for each affected label, preserving counts. JSON returns null metrics and the
`ambiguous_peer_label` not-comparable reason. Text and JSON both expose sorted
`ambiguous_labels` and `ambiguous_peer_samples`. The latter counts affected
samples, not duplicate rows or labels. The aggregate becomes
`insufficient_history` with `ambiguous_peer_labels`; unrelated labels retain
their own comparisons. The command's existing success/error and stream rules
are unchanged; insufficient history is a report verdict, not a new exit code.

The equal-sample-count split still drops an odd middle sample. That sample and
unobserved rows do not contribute ambiguity observations. Detection does not
prove that a remaining label has one stable origin: unknown labels, collisions
across different samples and already-redacted historical URI parts cannot be
resolved by this change. First-row per-label counts do not become per-link
measurements. Stored history remains role-writable and unauthenticated; no
origin, immutability, API truth, liveness or statistical-confidence claim is made.

The aggregation is separated into named stages for window facts, report
construction, freshness, sample folding, comparisons and verdict. Each stage
uses normal entry/result/error tracing; ambiguity state events use fixed labels
without private URI parts. This preserves one bounded history snapshot, reason
ordering, thresholds, strict projected booleans, finite arithmetic and no API
calls or history writes. No alert IDs, pending payloads, queues, cursors or
acknowledgement semantics change. See [the interaction contract](UI_MAP.md).

## Qualification and compatibility

The local composed source passed **567 tests**, all nine configured gates,
**4623/4623 production statements and 1696/1696 branches**, with zero exclusions.
Forty deterministic full-report comparisons against the inline #64 version
preserved results, apart from the intentionally clarified label-policy text.
Original-main ambiguity and missing-helper-tracing controls failed their
specific regressions as required; the composed implementation passed.
These are finite offline synthetic checks, not live node or deployment evidence.
Existing read-only QA tools are reused; no packages or interpreter are changed.
Check Actions for the exact published commit, not an earlier constituent run.

The common 23-module layout is unchanged. An external provisioner must review
the new `core.py` and `telemetry.py` hashes and qualify its own installation.
Existing [state custody](STATE_CUSTODY.md), [worker identity](WORKER_IDENTITY.md)
and [5.12.1 recovery barriers](RELEASE-5.12.1.md) remain in force. This release
changes no stored format; it does not waive older pending/Atlas/admission-marker
downgrade barriers. Preserve exact preimages, quiesce affected workers during
publication and keep reached/mixed bytes stopped until coherent repair. No
automatic old-reader rollback or integrity-baseline acceptance is authorized.
