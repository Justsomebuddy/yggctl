# Changelog

## [Unreleased]

### Added

- Console-only source repository, MIT license, contributor guidance, security
  policy and documentation of external integration requirements.
- Commit-pinned, read-only Python regression CI with bounded job duration.
- Reproducible Ruff/Mypy/Pytest/coverage configuration and QA-only tool pins.
- Negative origin-port and fail-closed shared-helper integrity regressions.
- Modular adversarial and property tests: 243 unique cases, 1000 Hypothesis
  examples, exact 100% production statements/branches without new exclusions.
- Local bounded numeric mutation, symbolic and seeded parser fuzz checks;
  their limited scope and native ABI boundaries are documented.

### Changed

- Console source is grouped under `yggctl/`; the Go decoder and deployment
  material are intentionally not included, including in reachable history.
- Offline fixture paths no longer depend on the original checkout location;
  broker tests handle long Linux temporary paths.

### Source cleanup (5.7.2 → 5.7.3, unreleased)

- Format Python source consistently, remove unused imports and annotate the
  verified-parent set without relaxing validation or typing rules.
- Preserve origin-port parsing side effects that reject malformed/range errors.
- Check unannotated function bodies with Mypy; type heterogeneous JSON
  boundaries and process streams without blanket diagnostic suppression.
- Retain strict IPv4 parsing while removing unreachable redundant comparisons;
  explicitly reject zero ports through the existing range validation.
- Normalize Unicode/non-decimal and overlong numeric conversion failures to
  the safe CLI error contract; add red/green adversarial regressions.
- Expand CI from stdlib smoke tests to lint/types/security/regressions and an
  exact 100% statement/branch gate; no deployment or remote change.
- Extract logged shared fixtures and prevent duplicate inherited Pytest cases.
- Require `test_support.py` in root integrity coverage because it is imported
  by regression suites. External provisioners must review/update their exact
  manifest before deploying this source; this repository does not do so.
- Explain narrow reviewed Bandit exceptions; retain actual coverage and missing
  broad-SAST limitations rather than advertising a full security pass.
- Document GitHub Issues and pull requests as the contribution/reporting route,
  with synthetic reproducers and no disclosure of operational secrets.

The source version is 5.7.3; installed files and the running node are unchanged.
No stable release, generic installer or live deployment is claimed.
