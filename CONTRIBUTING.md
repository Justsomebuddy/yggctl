# Contributing

Read [the README](README.md), [development boundaries](DEVELOPMENT.md) and
[the integration contract](docs/ARCHITECTURE.md) first. This is reference source,
not an installer or a supported universal Yggdrasil management application.

Keep changes small and include regression tests. Run all three Python suites
from the README, describe what changed and why, and identify anything not
tested. Use synthetic examples; never attach live configuration, identities,
raw logs or operational databases. Update the matching documentation when
behavior, prerequisites or command effects change.

Use a topic branch and a focused pull request. Security-sensitive changes,
dependencies, CI permissions and runtime integration deserve explicit review.
Do not claim an independent clean-room implementation or compatibility beyond
the evidence available. Check third-party rights before adding external code.

Report bugs and proposals through
[GitHub Issues](https://github.com/Justsomebuddy/yggctl/issues); propose changes
through pull requests, not direct pushes to the default branch. Follow
[SECURITY.md](SECURITY.md) for report content and sensitive-data handling.
