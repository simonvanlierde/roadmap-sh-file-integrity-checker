# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release. If you ran a copy from `main` before it:

- **Breaking:** a signing key that other users can read or write, or that belongs to
  another user who isn't root, is now an error. Run `chmod 600` on the key file.
- **Breaking:** an empty key file is now an error. Before, bash and Rust signed with a
  zero-length key and Python wrote an unsigned store, so that baseline was never
  protected. Move the old store aside, point `INTEGRITY_KEY` at a path that doesn't exist
  yet, and run `init`: it creates a new key and a signed store.

### Added

- The same checker three times, in bash, Python (stdlib only) and Rust. All three read
  and write one store format and print the same messages.
- `init`, `check` and `update` on a file or a directory. Exit code 0 means clean, 1 at
  least one discrepancy, 2 a usage or environment error.
- `check --fast`, which re-hashes only files whose size or mtime changed.
- Store signing with an HMAC-SHA256 key file set in `INTEGRITY_KEY`. The first `init`
  creates the key when it does not exist.
- A threat model in [docs/threat-model.md](docs/threat-model.md).

[Unreleased]: https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/commits/main
