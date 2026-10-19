# Verification scope

## Local candidate qualification (2026-10-19)

The unreleased 5.7.3 working tree was tested offline on Linux with Python
3.14.8: read-only source, empty operator home, RAM-only intermediate state,
user/mount/PID/network namespaces and CPU/memory/process/time limits. Only
allowlisted sanitized tool fields were persisted. No live node, host services,
installed files, packages or production manifests were changed.

| Check | Result and scope |
| --- | --- |
| Syntax | All 36 Python files parse |
| Ruff 0.15.6 | Configured E4/E7/E9/F rules and format check: PASS |
| Mypy 1.19.1 | Python 3.14 target, including unannotated function bodies: PASS; not strict typing |
| Bandit 1.9.4 | Recursive runtime and test scan: zero unsuppressed findings; high-severity JSON integrity check PASS |
| Pytest 9.0.2 | 243 unique tests collected and passed; third-party plugin autoload disabled |
| Independent stdlib suites | 100 console + 23 research + 33 atlas: PASS |
| Coverage 7.13.0 | **100% statements (3369/3369), 100% branches (1218/1218)** across 18 production modules; zero excluded statements or partial branches |
| Hypothesis 6.151.9 | Five deterministic properties, 1000 passing examples, zero failing examples; no persisted example database |
| Explicit mutation check | All 14 selected numeric-parser body mutants killed by tests on Python 3.14; original passes; logging decorators preserved |
| CrossHair 0.0.102 | Two bounded numeric wrapper postconditions confirmed; no incomplete conditions; supplemental Python 3.11 host only |
| Atheris 3.0.0 | Seeded journal/peer-URI harness: 5000 runs, 94 instrumented edges, no crash; supplemental Python 3.11 host only |
| Gitleaks 8.30.1 | Controls PASS; all 13 reachable commits, 36 candidate tracked files and 18 new publication files: zero findings in three independent offline scopes |
| Vulture 2.15 | PASS at 80% minimum confidence |
| Radon 6.0.1 | Metrics measured; maximum cyclomatic complexity 44, not a quality/security gate |
| Semgrep native engine 1.175.0 | Three local rules: 36 files, zero findings/errors; three-rule positive control passed |
| CI configuration | YAML and embedded Python validated; exact nine-stage quality controller replayed offline successfully; hosted run **not run at local qualification**; check Actions for current status |

These are **working-tree candidate** results, not a hosted pass for a new SHA
or evidence of a secure live deployment. No push was made during that local
qualification; this is not a continuously updated hosted-run status. Check
[Actions for the exact commit](https://github.com/Justsomebuddy/yggctl/actions). The
original hosted baseline had 155 tests; its success does not qualify this tree.
The local CI replay used already-approved tools, not the hosted installer or
Actions setup. Native supplemental tools use their available matching 3.11 ABI;
they are not evidence of Atheris/CrossHair compatibility with Python 3.14.

### What the coverage means

Coverage includes all production Python modules. Only the three legacy
`tests.py` suites and their shared `test_support.py` fixture helper are omitted;
supplemental `tests/` is outside the runtime source scope. No new exclusions,
`pragma: no cover` or partial-branch bypasses were introduced. The CI gate checks
actual missing statement/branch counts and zero exclusions, not rounded output.
The local coverage report also enforces the requested `fail_under = 100`.

Tests exercise successful results, rejection contracts, hostile inputs, bounded
I/O, custody checks, SQLite failures, transaction rollback, recovery and CLI
handlers using synthetic fixtures and controlled failure injection. They do not
exercise real service mutations. Two unreachable IPv4 reserialization guards
were removed while retaining both strict IPv4 parses and rejection regressions;
port absence is distinguished from zero before the existing explicit range check.

An additional adversarial regression found that Unicode `isdigit()` glyphs and
an overlong decimal string could leak `ValueError`. Conversion errors now become
the existing safe numeric `Failure` label; valid decimal inputs remain accepted.
**100% coverage did not discover this by itself and is not a correctness proof.**

### Reviewed Bandit exceptions

Ten narrow inline test-ID exceptions have preceding rationale comments:
subprocess imports (B404), reviewed argv-only subprocess calls (B603), and the
broker directory's traversal mode `0711` (B103). No security rule is disabled
repository-wide. The broker socket remains owner-controlled `0600` with peer
credential checks; a static exception is not proof of deployed isolation.
Redaction fixtures are explicitly synthetic non-secret test data.

### Secret-scan and SAST boundaries

The official temporary Gitleaks archive was checked against its release SHA-256.
Same-release TLS checksums provide integrity, not independent signature
verification. It was not installed system-wide. Scans use built-in rules,
no project allowlist/baseline, no inline allow directives and no online
verification. Ignored private operational notes and QA evidence are excluded
from publication, not silently treated as scanned public material. A clean
bounded scan cannot prove the absence of every possible secret.

The reviewed [local Semgrep rules](../qa/semgrep.yml) detect dynamic `eval`/`exec`,
explicit shell execution and selected unsafe deserialization calls. All three
have a positive control. This is **not** a community ruleset or taint-flow audit.
The incomplete installed frontend was not used: the native engine scans an
explicit target manifest. A read-only public CA bundle and synthetic service/
protocol/hosts/resolver files permit initialization; networking stays disabled.

## Reproducing source checks

Runtime code is standard-library-only. QA tools are optional development tools;
`requirements-dev.txt` pins direct versions, not transitive dependencies/hashes.
Prepare an operator-approved isolated tool environment separately. Commands do
not authorize an installation, interpreter upgrade or production operation.

From the repository root with those tools available:

```sh
ruff check .
ruff format --check .
mypy
bandit -q -r yggctl tests
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -B -m pytest --collect-only -q
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -B -m coverage run -m pytest -q
python3 -B -m coverage report
```

Use a disposable offline Linux sandbox, read-only source and separate writable
private RAM state for `MYPY_CACHE_DIR`, `COVERAGE_FILE`,
`HYPOTHESIS_STORAGE_DIRECTORY` and Pytest's `-o cache_dir=...`. Capture and
sanitize tool output before terminal/disk; never save raw diagnostics/corpus.
Autoload is disabled to avoid unrelated operator plugins. To inspect property
statistics, explicitly load only `hypothesis.extra.pytestplugin` with
`-p hypothesis.extra.pytestplugin --hypothesis-show-statistics`.

`pyproject.toml` discovers both legacy and supplemental tests without inherited
duplicate cases. Supplemental tests require the QA-only Hypothesis dependency;
the three README stdlib suites do not. Ruff's conservative 3.11 grammar keeps
analyzer-parser compatibility; runtime qualification is 3.14. Mypy checks
unannotated bodies without blanket missing-import suppression; dynamic JSON
boundaries and unannotated signatures still prevent a strict-typing claim.

## Hosted CI

The commit-pinned, read-only source-quality workflow runs syntax, Ruff lint and
format, Mypy, both Bandit checks, Pytest collection/regressions and an exact
100% production statement/branch gate on Ubuntu/Python 3.14. It does not deploy,
use repository secrets or persist checkout credentials. Tool installation and
analyzer streams are captured and discarded; logs contain stage/count results.

Hosted setup may download Python/actions/tool dependencies. Unlike local QA,
the hosted VM is not a per-tool no-network namespace. The temporary state lives
in the disposable runner; no coverage/corpus artifact upload is configured.
Hosted CI does not run Gitleaks, Semgrep, mutation, symbolic or fuzz checks;
those are separate local reviewed gates. Verify the actual run and head SHA
after an approved push; local replay cannot prove hosted success.

## Explicit limits and checks not qualified

* Full Python Test Lab v3 parity, continuous thermal/cgroup/double-fork proof,
  broad community SAST and whole-program formal verification are not claimed.
* Mutmut 3.5 skips decorated functions, including these logged helpers. Its
  attempted native pilot did not produce a valid production mutation score.
  The separate 14-mutant check is narrowly scoped, not whole-program coverage.
* Symbolic checks cover two selected wrapper contracts; fuzzing is bounded and
  seeded, not exhaustive. Neither native supplemental tool qualified 3.14 ABI.
  There are no production deal/icontract contracts to lint/test/prove.
* No online CVE lookup or transitive dev-tool lock audit was run. Runtime uses
  the standard library; the unrelated operator environment is a different audit
  object. Pins are not vulnerability guarantees or a complete reproducible lock.
* Fresh-machine provisioning, other runtime Python/Yggdrasil versions, actual
  root/worker installation, service/firewall changes, the external decoder,
  real key rotation/rollback/network behavior and SimpleX delivery/ACK remain
  unqualified. There is no universal-portability or production-readiness claim.
