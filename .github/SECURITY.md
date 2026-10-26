# Security

## Report a vulnerability

Report it privately, through
[a GitHub security advisory](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/security/advisories/new)
or by email to <90462640+simonvanlierde@users.noreply.github.com>. Don't open a public issue or pull request for it:
anyone can read those before there is a fix.

Please include:

- What the problem is and where it is: a file, a function or a dependency.
- Steps to reproduce it, or a proof of concept.
- The impact you expect, and the version or commit you saw it in.

I acknowledge a report within 14 days, then tell you whether I can reproduce it and when I
expect a fix.

## Fixes and disclosure

A fix ships in a new release. When it is out, I publish the GitHub security advisory for
it, with a CVE where one applies, and credit you unless you'd rather not be named. The
CHANGELOG entry for that release links the advisory.

## Scope

In scope:

- The bash, Python and Rust implementations, and the release binaries built from them.
  [docs/threat-model.md](../docs/threat-model.md) says what the tool defends against.
- The CI and release workflows in `.github/workflows`.
- The Rust dependencies in `rust/Cargo.lock`, when the problem affects this tool.

Out of scope:

- A problem in a dependency that doesn't affect this project. Report it upstream.
