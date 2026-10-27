# Source5.13.0 — observed stored-history throughput

New read-only `yggctl throughput [hours]`: default24, integer1..72, existing bounded
metrics window. Mean and peak Mbit/s are observed counter deltas, not link capacity,
application goodput or remote availability. No API/network requests, schema writes,
service changes or firewall changes. The generated result explicitly declares
unverified role-writable history, not authenticated/immutable observations.

Independent regressions cover invalid/missing middle samples, unassignable rows,
conflicting duplicates in both orders, duplicate timestamps, invalid-counter
identity collisions, unknown invalid-record positions and recovery only after two
new valid adjacent samples. Identical duplicate observations remain deduplicated.
A display label covering multiple links is withheld. Existing finite numeric,
reset and600s gap bounds remain. Contribution commits are retained as ancestors;
owner follow-ups preserve existing5.12.5 underlay and held-send contracts.

Qualification receipts bind the exact published commit and actual CI. Local
source QA and a repository merge alone are NOT installed-host qualification;
provisioning/deployment remain external and separately authorized. This is not a
whole-program correctness or historical-authenticity guarantee.

Local qualification: 629 tests, all9 configured gates; 4823 statements/1768 branches,100% with zero missing or excluded. Original-head transplant
fails independent boundary assertions; synthetic/no-network tests only.
