# Contributing

Thank you for your interest in the file integrity checker. It does what it set out to do, so I fix bugs and
keep its dependencies current, but don't plan new features. Bug reports and pull requests
are welcome. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) first, and report
vulnerabilities as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## Report a bug

Open an [issue](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/issues). Say what you did, what
you expected and what happened, with your OS and the commit or version you used.

## Check a change

`./test.sh` runs one scenario against each implementation and checks that all three
write byte-identical stores, and `./difftest.sh` compares them on 50 random trees. Both
need the Rust build (`cargo build --manifest-path rust/Cargo.toml`). A change to the store
format goes into all three implementations in the same pull request. The README's
[Tests and benchmarks](../README.md#tests-and-benchmarks) section has the rest.

## Write commits and pull requests

- **Commits** follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):
  `type(scope): summary`, in the imperative, lower case, with no period.
- **The pull request title** becomes the squash commit subject, so it follows the same rule.
- **The changelog** ([CHANGELOG.md](../CHANGELOG.md)) follows
  [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). Add an entry for a change
  users will notice, written for them rather than as a commit subject.

## Who maintains this

Simon van Lierde maintains the file integrity checker: reviews pull requests and merges them. The
repository belongs to [simonvanlierde](https://github.com/simonvanlierde) on GitHub. Only
maintainers can merge to `main`. If no maintainer can continue, the repository is archived
with a note in the README, and anyone may fork it under its license.
