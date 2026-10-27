# Source5.14.0 — scoped read-only overlay-policy diagnosis

`sudo yggctl overlay-policy [interface]` reads local TUN details, active firewalld
zone membership and nft JSON. It changes no rules, zones, interfaces, service,
peer/key, underlay or integrity baseline and sends no probe packets. A no-TUN
SOCKS-only installation is not repaired or reconfigured by this command.

The static result is for one named filter/output base chain and hypothetical
destination200::1. Output uses `sample_scope` and `sample_verdict`, never an
unqualified `overlay_verdict`; `host_permission=unknown` and
`reachability=not_tested` are mandatory. Zone membership is not permission; the
interface name is an explicitly unverified role heuristic. Other chains, hooks
and routing remain outside scope, even when this sample is allowed.

limit/quota and unknown state/predicates stay conditional. jump/goto are explicitly
unsupported rather than falsely simulated. Unknown conditions cannot disappear
at a return. Type checks prevent malformed-match crashes; malformed indexed
members fail closed instead of vanishing. Prefix operands use the native nft JSON
schema and validate every set member; item/expression/path budgets are finite.
Missing, failed and invalid command output is disclosed, not treated as evidence
of absence. The original contribution ancestry is retained with owner fixes.

Independent synthetic counterexamples cover all reported blockers, scope and real
JSON operands; original-head transplants must fail assertion controls. Source
quality/CI is distinct from external host deployment qualification. No complete
nft evaluator, host-security clearance or production-readiness claim is made.

Local source qualification: 675 tests, all9 configured gates,5035 statements/
1890 branches,100% and zero exclusions. Original-head helper transplant produces
7 genuine assertion failures (subtests included), no collection/tool errors.
