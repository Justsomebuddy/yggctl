# Historical report interaction contract

## 2026-10-20 — source 5.7.5

| ID | Invocation | Expected result | Bounds and failure behavior |
|---|---|---|---|
| CLI-RESEARCH-REPORT | `research report [1..72 hours]` | JSON/Markdown report with existing historical samples, quantiles and explicit gaps | Accept the collector's complete 10,000–12,000 record retention cycle before selecting the requested time window; over-limit/corrupt data remains unknown, not fabricated history. |
| IPC-RESEARCH-METRICS | Research worker requests saved metrics through its broker | Full supported raw file, without truncation or silent history loss after encoding | Raw limit 32 MiB; metrics reply limit is `4 * ceil(raw_limit / 3) + 12` bytes, including compact JSON and newline. Other admin replies retain 24 MiB. |

No new command, option, output schema, external request or automatic data cleanup.
These are synthetic offline regression contracts, not proof of any deployment's
systemd provisioning, privilege isolation or overlay connectivity.

## Sandbox command boundary (5.7.6)

All `atlas`, `research` and remote commands fail before worker launch when the
parent integrity check fails. Research broker requests stay local-only; Atlas
crawl retains its three remote debug reads. Command syntax/output is unchanged.
