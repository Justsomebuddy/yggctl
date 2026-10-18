# Changelog

## [Unreleased]

### Added

- Console-only source repository, MIT license, contributor guidance, security
  policy and documentation of external integration requirements.
- Commit-pinned, read-only Python regression CI with bounded job duration.

### Changed

- Console source is grouped under `yggctl/`; the Go decoder and deployment
  material are intentionally not included, including in reachable history.
- Offline fixture paths no longer depend on the original checkout location;
  broker tests handle long Linux temporary paths.

No production console behavior, installed files or running node is changed by
this repository preparation. The runtime version remains 5.7.2. No stable
release or generic installation support is claimed.
