# Source 5.12.5 — stale underlay snapshot rejection

## Change

Incorporates PR #70 (`8fe0cc9171df318f407e1829a0090c8f2c83cd9e`) on the
5.12.4 main base `a63b406dabaf753d4496eb5d1868460ca8da3070`. Before returning
successful socket/conntrack proof, read both service PIDs again and repeat both
PID exclusion checks. Reject changed/stopped services, changed exclusions and
unavailable final reads. Preserve the original contribution commits.

The existing mode transaction compensates on failure. Compensation and explicit
recovery must prove the restored underlay before removing or archiving the
journal. A failed proof retains retryable evidence; it is not a successful
rollback. Neither the journal format nor network policy is changed.

## Finite qualification

The six contribution regression methods and three independent methods cover
both stable modes, PID changes/stops, changed exclusions, final-read failure,
ordering/noise/unrelated exclusions, automatic compensation and a failed explicit
recovery followed by a successful retry. Synthetic adapters only: no live mode
switch, service restart or network request. The old checks module transplanted
onto these tests produces genuine assertion failures, not collection/tool errors.

Final local source qualification: 600 tests, all nine configured gates,
4664/4664 statements and 1704/1704 branches, zero exclusions or missing branches.
The three independent stdlib suites remain 93 console, 24 research and 33 atlas.
Runtime uses existing Python 3.14.8; static tools reuse their existing Python
3.11 host with the configured target. No interpreter/package change.
Check Actions for the exact published SHA; local qualification does not imply
hosted CI success or authorize installation on an existing machine.

## Limits and handoff

The final reads are sequential observations, not an atomic snapshot, a process
identity proof or PID-reuse protection. Changes can occur between the final
reads or after return. This patch narrows stale evidence acceptance; it cannot
promise future traffic routing or uninterrupted operation.

An external operator must qualify the exact source/manifest delta and rollback
before installation. No generic installer, firewall acceptance, runtime mode
switch, node update, shared-service restart or alert resend is bundled here.
The 5.12.4 outbound hold and ambiguous-send rules remain unchanged.
See [interaction contract](UI_MAP.md) and [architecture](ARCHITECTURE.md).
