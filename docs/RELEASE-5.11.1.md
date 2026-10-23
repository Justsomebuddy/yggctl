# Source 5.11.1 — report streams and event windows

This source patch release composes two bounded CLI changes: machine-readable
trend output (#45) and independent event lookback/record limits (#46).
The [5.11.0 trend measurement/trust contract](RELEASE-5.11.0.md) and
[5.10.0 migration/recovery rules](RELEASE-5.10.0.md) remain in force.
This repository remains reference source without a general-purpose installer.
Publication alone updates no installed runtime, profile, service or host policy.

## Trend JSON stream contract (#45)

On a successful `trend [hours] json` invocation, **all stdout is exactly one
JSON report**. The human `[done] errors=0 elapsed=...` summary goes to stderr,
including when the report verdict is `insufficient_history`. Do not combine
stderr with stdout before JSON decoding. Existing `--trace` uses the existing
trace channel, not JSON stdout.

A failed trend invocation retains its existing nonzero status and `FAIL` on
stderr, with no successful JSON report or success summary on stdout. Text-mode
trend retains its completion line on stdout. Argument order, history schema,
readability/privilege requirements and trend measurement semantics do not change.
Empty in-window history remains a controlled failure; it is not a successful
empty JSON report. An emitted `insufficient_history` report is not evidence of
healthy connectivity.

## Event lookback and visible limit (#46)

`events [hours]` accepts integer hours 1..72, default **6**. Hours select the
journal lookback only; they no longer also cap the number of records. The
visible limit is independently **1000 newest matching records** from the
existing node/stack journal query. `logs [N]` retains its existing line-count
behavior, including default 50 and accepted range 1..1000.

The command requests at most **1001 records** as an overflow probe. It parses
and applies existing message redaction to all returned records, including the
probe record, before selecting the newest 1000-record suffix. Journal-provided
order is retained; records are not independently sorted or deduplicated by
realtime timestamp. Equal timestamps and backwards realtime do not change the
suffix-selection rule.

The result preserves `logs` and adds:

- `window_hours`: requested lookback;
- `limit`: 1000;
- `returned`: number of visible records;
- `truncated`: whether more than 1000 records were returned by the bounded query.

Exactly 1000 records gives `truncated=false`. More than 1000 gives
`truncated=true` and `WARN events_truncated` on stderr. The number omitted is
unknown. A bounded successful view remains rc0; narrowing the time interval or
a separately reviewed journal query may be needed for omitted history. Neither
flag value proves a complete historical journal: current access, retention and
source availability still limit the query.

Event output retains the existing human completion line on stdout. It is **not**
the machine-only stdout contract provided by `trend ... json`.

## Failures, resource and operational boundaries

Invalid arguments fail before reading the journal. External command failure,
timeout, byte overflow or malformed journal JSON remains nonzero; no partial
log projection is presented as successful. Existing default **20-second** command
timeout, **16 MiB stdout / 1 MiB stderr** limits and whole-message sensitive-data
redaction remain in force. These are bounded command-output limits, not a total
memory or whole-operation timing guarantee.

The changes add no privileges or listeners and perform no journal deletion,
service mutation, profile provisioning, network-policy change or accepted-baseline
update. They do not change alert delivery or acknowledgement semantics.

## Qualification scope — 2026-10-23

The complete composed source was checked offline with Python 3.14.8. All nine
required stages passed: syntax, Ruff, formatting, Mypy, both Bandit checks,
Pytest collection, tests and coverage. **456 tests passed; 4213 statements and
1534 branches were covered 100%, with 0 missing lines/branches and 0 exclusions.**
The independent stdlib suites also passed separately: 93 console, 24 Research,
33 Atlas. Those 150 cases are already present in the complete suite, not 150 extra
unique cases. Both original-base negative controls reproduce their defects;
the final source passes the same regressions plus independent hostile-boundary,
trace/error and entrypoint contracts.

Reproduction uses the commands in [verification](VERIFICATION.md#reproducing-source-checks)
and the separate stdlib invocations in [README](../README.md#inspect-and-test-without-installing).
The final integration PR must also pass all hosted gates at its exact head before
merge; its attached check and Git history bind the actual head/tree and outcome.
A previous contribution's green run is not qualification of the composition.

The finite regression scope includes actual `main()` stream separation,
insufficient/empty history, trace and rejection paths; event hours/default/count
boundaries, overflow/order, redaction, malformed records, external failures and
existing byte/time limits; and original-base negative controls. A previous
contribution's green run does not qualify the final composition.

Synthetic adapters and offline source tests do not qualify a real journald,
installed console, provisioned node, service sandbox or native transport. No
exhaustive correctness, complete-history, live health, origin/authenticity,
exactly-once delivery or human-ACK claim follows from these changes or coverage.
See [CLI interaction map](UI_MAP.md) and
[reproduction instructions](VERIFICATION.md#reproducing-source-checks).
