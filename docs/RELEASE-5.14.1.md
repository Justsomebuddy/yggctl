# Source5.14.1: research calendar-boundary errors

## Correction

UTC conversion can exceed Python's representable calendar even when an ISO
string parses successfully. Normalize this failure into the existing
`research_invalid_timestamp` instead of leaking an unhandled overflow. Preserve
`research_naive_timestamp` for naive inputs. Independently normalize underflow
when subtracting a valid1..72h metric window from its end timestamp.

A bad metric row increases `invalid_records`; a good neighbor remains usable.
Invalid stored snapshots are rejected with the typed error, not silently changed.
No snapshot/metric format, acquired history, provenance, dependency, privilege,
node configuration, policy, service lifecycle or notification behavior changes.

## Validation and limits

Synthetic tests cover both calendar edges, snapshot started/finished fields,
metric rows and end time, exact representable window bounds, valid offset
normalization and real synthetic report artifacts. Original-source transplants
must fail causal regressions. Final local quality/coverage and published CI are
recorded for the exact release commit; this is not a general installation claim.

Impact is local-history robustness, not an established remote-node exploit.
The system-clock-derived window in `research.report` remains a separate edge:
a synthetically injected year1 clock can still underflow there. No global
catch-all or claim that every calendar overflow is handled is added.

[Interaction contract](UI_MAP.md#research-calendar-boundary-failures-5141).

## Source qualification

682 tests pass across all nine quality gates. Production coverage is100% for
5038 statements and1890 branches, with zero exclusions. Independent synthetic
report-path tests accompany the four timestamp/window regressions. The three
existing stdlib suites retain their93/24/33 cases. Installation is independently
qualified by the operator; source checks alone do not certify host health.
