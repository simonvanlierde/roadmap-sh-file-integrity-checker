# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-21

### Added

- The same checker three times, in bash, Python (stdlib only) and Rust. All three read
  and write one store format and print the same messages.
- `init`, `check` and `update` on a file or a directory. Exit code 0 means clean, 1 at
  least one discrepancy, 2 a usage or environment error.
- `check --fast`, which re-hashes only files whose size or mtime changed.
- Store signing with an HMAC-SHA256 key file set in `INTEGRITY_KEY`. The first `init`
  creates the key when it does not exist. The key file must be private: mode 600, owned by
  you or root.
- A threat model in [docs/threat-model.md](docs/threat-model.md).

[0.1.0]: https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/releases/tag/v0.1.0
