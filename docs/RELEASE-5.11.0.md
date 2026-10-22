# Source 5.11.0 — stored-history trend

This source release integrates the `trend` contribution (#42/#43) with owner
follow-ups for numeric safety, observation semantics and truthful provenance.
This repository remains reference source without a general-purpose installer.
Publication alone changes no installed runtime, deployment hook or network policy.
The [5.10.0 migration/recovery rules](RELEASE-5.10.0.md) remain in force.

## Command and measurement contract

`trend [hours] [json]`: integer hours 1..72, default 24, optional `json` last.
Duplicate/reordered arguments fail rather than silently overriding earlier ones.
The report reads one bounded local history snapshot, makes no admin API query,
and writes no history, queue or cursor. It needs readable metrics; it does not
weaken role permissions to obtain them.

The timestamp-sorted in-window samples split into equal **sample-count** halves;
an odd middle sample is dropped. This is not an equal elapsed-time split,
time-weighted uptime, independent statistical confidence or a live health gate.
Duplicate rows retain their metric weight, but the minimum requires eight distinct
timestamps. Cadence is the median positive timestamp interval. Long/sparse
sampling does not prove continuous coverage. Thresholds are policy heuristics:
median drift against max(floor, 3×baseline MAD), with direction by metric.

Node up-count uses observed samples; degraded-sample share uses every selected
sample. For each sanitized displayed endpoint, availability is strict-true count
conditional on present rows with a strict boolean state. Answered, absent,
unobserved and invalid-state counts are distinct; absence is not fabricated down.
RTT is **protocol router-response EWMA**, not link or application delay. A genuine
zero value remains valid. The report does not infer a raw API key or authenticated
peer identity from these stored schema-2 projections.

First row per displayed endpoint/sample wins. Credentials are removed again at
rendering, but unknown labels or sanitized collisions may combine unrelated
origins, and changed ports may split one peer into multiple series. These labels
are not stable per-link identities.

## Insufficiency and numeric boundaries

Insufficient evidence is explicit: fewer than eight distinct timestamps, less
than 30 minutes span, no observed samples, more than 25% unobserved, stale history,
future timestamps, malformed peer containers or no comparable observed metric.
Collector stale means age > max(10 minutes, 3×median cadence). Future samples are
counted from the same snapshot and cannot silently make a report fresh. No
in-window samples remains a controlled failure, including future-only history.
Error-free rows alone cannot confer a stable observed-connectivity verdict.

Untrusted numeric fields accept finite nonnegative int/float values, not bool,
strings or unrepresentably large integers. Safe midpoint arithmetic avoids
finite-input median overflow. An unrepresentable MAD threshold yields null with
explicit `arithmetic_overflow`; missing valid values yield a separate reason.
There is no silent numeric clamp, nonfinite JSON, historical rewrite or deletion.
A caller-owned local validation audit batches checked/rejected counts, avoiding
per-value journal flooding and thread-global logging switches.

## Trust boundary

Generated text and JSON visibly label history **unverified, role-writable and
unauthenticated**, with `authenticated=false` and
`immutable_since_capture=false`. A same-role writer can alter historical values;
validation, local identifiers or checksums do not authenticate them. No origin,
immutability, signature or API-truth guarantee is provided. Trend verdicts cannot
serve as an incident clearance, live liveness assertion or delivery/human-ACK proof.

## Qualification scope

Offline source regressions cover extreme arithmetic, strict projected booleans,
zero RTT, absent/unknown observations, future and duplicate timestamps, malformed
containers, explicit output trust/measurement semantics and read-only execution.
Local offline qualification: **430 tests passed**, all nine source quality
stages passed, **4,204 statements and 1,530 branches covered**, with zero missing
lines/branches and zero exclusions. The 412 pre-feature tests remain included.
These finite source checks do not prove correctness or a deployed node. Original supplied
network-stand observations and timing figures are not independently verified here
and are not release claims. See [CLI interaction map](UI_MAP.md#stored-history-trend-5110)
and [reproduction instructions](VERIFICATION.md#reproducing-source-checks).
