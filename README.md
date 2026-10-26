> Source **5.12.3** does not turn skipped collections into confirmed peer downtime.
> Long observation gaps restart unconfirmed outages; already-alerted recoveries
> disclose uncertainty without duplicating down events.
> See [compatibility and qualification](docs/RELEASE-5.12.3.md) and
> [state provisioning](docs/STATE_CUSTODY.md). No installer is bundled.

# yggctl

An experimental operator console for a specific Linux/systemd deployment of
[Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go). It combines node
health checks, peer management, local metrics and bounded network observations.
It is an independent project, not the Yggdrasil node or an official Yggdrasil
tool. It complements rather than replaces upstream `yggdrasilctl`.

> **Reference source, not a general-purpose installer.** Paths, services and
> privilege boundaries are deployment-specific. A standard Yggdrasil package
> does not provide all prerequisites. Running privileged commands on an existing
> host can stop services or alter configuration. No fresh-machine installation
> or production-readiness guarantee is provided.

## Integration notice

Separate worker principals and expected-unit admission require reviewed
[provisioning/migration](docs/WORKER_IDENTITY.md). Alert forwarding now requires
[Ygg-only native-handoff configuration](docs/NATIVE_HANDOFF.md): ambiguous attempts
remain pending without blind retry; local recording is not delivery/human ACK.
This source change never updates an installed console or shared alert bridge.
The 5.10.0 queue reader and writer must be upgraded together: retention metadata
is not compatible with an older forwarder/compactor. Ordinary-alert capacity
is unchanged; one additional bounded metadata record shares the existing byte cap.

Research reports, maps and diffs now visibly label saved snapshots as
**unverified role-writable history**. Structural validation and stable local
identity checks do not authenticate origin, immutability or API truth.

## Scope

This repository contains **only the Python console**, including its research
and atlas modules, synthetic regression tests and documentation. It does not
contain the node, Go configuration decoder, deployment scripts, systemd units,
host configurations, peer lists, operational data or private lab history.

The console uses the Python standard library. Some runtime commands require
external programs, including a separately provisioned `config-json` decoder;
see the [integration contract](docs/ARCHITECTURE.md). Offline tests mock those
dependencies. CLI help and some output are currently in Russian.

## Inspect and test without installing

The tested environment is Linux with Python 3.14. No package installation,
root access, running Yggdrasil node or Internet access is needed for the suites.
Choose the Python 3.14 interpreter available on your system; on the original
Debian test host it is `/usr/bin/python3`.

From the repository root:

```sh
cd yggctl
python3 -B tests.py
python3 -B -c 'from research.tests import run_suite; run_suite()'
python3 -B -c 'from atlas.tests import run_suite; run_suite()'
cd ..
```

The suites use temporary directories, mocked system commands and local Unix
sockets. Broker test fixtures use Linux `/proc/self/fd` to handle long checkout
paths. They do not exercise a provisioned node or prove runtime isolation.
The stdlib suites and supplemental Pytest cases cover synthetic behavior,
faults and boundary conditions. Exact tested-source evidence belongs to the
[release records](docs/RELEASE-5.12.3.md), not a timeless test-count promise.
Statement/branch coverage does not prove correctness or qualify a live deployment.
For lint, types, Pytest discovery and coverage, see the
[QA instructions](docs/VERIFICATION.md#reproducing-source-checks).

To inspect help only:

```sh
python3 -B yggctl/main.py --help
```

Help emits a run-summary entry to the local syslog. Do not try other commands
on a production host without reviewing their effects and dependencies.

## Stored-history trend

`trend [hours] [json]` accepts integer hours 1..72 (default 24); `json` must
come last, with no duplicated arguments. It reads the bounded local metrics
file, never calls the admin API and changes no gate, queue, timer or network
policy. Access still requires a readable file; unreadable role-owned data needs
reviewed privilege provisioning, not relaxed permissions.

The report compares equal sample-count halves, not equal elapsed-time halves.
Availability is conditional on **present rows with a strict boolean state**;
answered, absent and invalid-state counts are separate. Missing observations
are not invented down peers. RTT is protocol router-response EWMA, not link or
application delay. Sanitized endpoint labels are not verified peer identities.

## Report output streams and event windows

Successful `trend [hours] json` writes exactly one JSON document to stdout;
its human `[done]` summary goes to stderr. An `insufficient_history` report
uses the same stream contract. Failures remain nonzero with `FAIL` on stderr,
not an empty successful JSON report. Do not merge stderr into a JSON parser's
input. Text-mode trend output keeps its existing completion line on stdout.

`events [hours]` accepts 1..72 hours (default 6), independently of its visible
limit of 1000 newest matching journal records. A bounded 1001-record query
probes overflow: more than 1000 sets `truncated=true` and emits
`WARN events_truncated` on stderr; exactly 1000 does not. The result preserves
journal order and adds `window_hours`, `limit`, `returned` and `truncated`
alongside `logs`. Event output retains its existing human completion line on
stdout; this is not the machine-only trend JSON contract. Message redaction,
command byte/time bounds and `logs [N]` remain unchanged. Bounded success is not
proof of complete journal history under current access and retention.

## Documentation

* [Architecture and external integration](docs/ARCHITECTURE.md)
* [Security policy](SECURITY.md) and [operational limitations](docs/SECURITY.md)
* [Verification scope](docs/VERIFICATION.md)
* [Source 5.11.1 report-output contract](docs/RELEASE-5.11.1.md)
* [Source 5.11.0 trend contract](docs/RELEASE-5.11.0.md)
* [Source 5.10.0 contracts and qualification](docs/RELEASE-5.10.0.md)
* [Contributing](CONTRIBUTING.md) and [development boundaries](DEVELOPMENT.md)
* [Changelog](CHANGELOG.md) and [third-party references](THIRD_PARTY.md)

## License

Project code is licensed under [MIT](LICENSE). Yggdrasil and external tools
retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
