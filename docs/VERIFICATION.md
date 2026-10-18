# Verification scope

The repository contains three Python unit/regression suites: console, research
and atlas. They use synthetic fixtures, temporary paths, mocked node/system
commands and local Unix sockets. Linux `/proc/self/fd` is used in broker test
fixtures to avoid Unix socket path-length problems in long checkout paths.
Production paths and broker behavior are not changed by that fixture adapter.

## Preparation check (2026-10-19)

On the Linux preparation host with Python 3.14.8, the console-only working tree
passed 99 console, 23 research and 33 atlas tests in isolated namespaces with no
network route. Syntax checks cover all 21 Python files; selected Ruff rules
E9/F63/F7/F82 also pass. These working-tree results must be repeated on the
exact publication commit; they are not a hosted CI or deployment result.

Bandit reports 11 findings: 10 low-severity import/subprocess/synthetic-password
warnings and one medium B103 finding for the broker directory's `0711` mode.
That mode permits worker traversal, not directory writes; fixture tests check
directory ownership and the socket's `0600` mode. This is a reviewed tradeoff,
not a clean Bandit result or proof of a deployed host's effective confinement.

Use the [README commands](../README.md). The tested interpreter is Python 3.14
on Linux; other Python versions and operating systems are not qualified.
Tests need no root, network route or live node. They do not require the external
Go decoder because runtime calls to it are mocked.

## Checks to record for every publication

Record the exact Git SHA, toolchain, individual suite counts/results, syntax
and lint scope, documentation links, source parity and reachable-history review.
Keep raw scanner output and operational evidence private; classify findings
without logging candidate values. A clean bounded scan is not proof of absence
of every possible secret.

Repeat the suites against an archive of the exact commit in disposable Linux
user/mount/PID/network namespaces with read-only source and isolated writable
temporary storage. Passing mocked tests is not evidence of a secure deployed
sandbox, delivery of alerts, or Internet/overlay reachability.

## Hosted CI

The `Regression tests` workflow checks Python syntax and runs all three suites
on an Ubuntu-hosted runner with Python 3.14. It grants only `contents: read`,
pins actions to full commit SHAs, does not persist checkout credentials, and
contains no deployment step or repository secrets. The workflow does not
isolate the hosted runner's network; action/Python setup may download tools.

The first hosted result must be checked after the initial push and tied to its
head SHA. Do not infer a hosted pass from local execution of equivalent commands.

## Not qualified

Fresh-machine provisioning; runtime compatibility with arbitrary Yggdrasil
versions; actual root/worker deployment; service or firewall mutations; external
decoder behavior; key rotation; rollback; complete network coverage; SimpleX
delivery/ACK. No claim of universal portability or production readiness is made.
