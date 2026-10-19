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
The stdlib suites contain 100 console + 23 research + 33 atlas tests.
With QA dependencies, Pytest also runs supplemental adversarial/property cases:
243 unique tests, with measured 100% production statement and branch coverage
on Python 3.14.8. This does not qualify a live deployment or prove correctness.
For lint, types, Pytest discovery and coverage, see the
[QA instructions](docs/VERIFICATION.md#reproducing-source-checks).

To inspect help only:

```sh
python3 -B yggctl/main.py --help
```

Help emits a run-summary entry to the local syslog. Do not try other commands
on a production host without reviewing their effects and dependencies.

## Documentation

* [Architecture and external integration](docs/ARCHITECTURE.md)
* [Security policy](SECURITY.md) and [operational limitations](docs/SECURITY.md)
* [Verification scope](docs/VERIFICATION.md)
* [Contributing](CONTRIBUTING.md) and [development boundaries](DEVELOPMENT.md)
* [Changelog](CHANGELOG.md) and [third-party references](THIRD_PARTY.md)

## License

Project code is licensed under [MIT](LICENSE). Yggdrasil and external tools
retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
