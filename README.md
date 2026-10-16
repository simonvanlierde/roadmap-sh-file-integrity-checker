# File integrity checker

[![CI](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is my solution to the <https://roadmap.sh/projects/file-integrity-checker> exercise. I
wrote it three times: in pure bash, in Python and in Rust. All three read and write the same
file format and print the same messages, so you can swap one binary for another on the same
baseline store.

```text
bash/integrity-check                  # bash, uses sha256sum or shasum
python/integrity-check                # python 3, stdlib only
rust/target/release/integrity-check   # cargo build --release --manifest-path rust/Cargo.toml
```

## Usage

```console
$ ./bash/integrity-check init ~/notes
Hashes stored successfully. (38 tracked, /Users/you/.integrity.db)

$ ./rust/target/release/integrity-check check ~/notes
/Users/you/notes/ideas.md: Unmodified
/Users/you/notes/new.md: Untracked
/Users/you/notes/old.md: Missing (file deleted)
/Users/you/notes/todo.md: Modified (hash mismatch)
```

| Command | Effect |
| --- | --- |
| `init <file\|dir>` | Hash every file under the target and write the baseline. |
| `check [--fast] <file\|dir>` | Re-hash and compare against the baseline. |
| `update <file\|dir>` | Re-baseline the target after a legitimate change or deletion. |

`init` and `update` rewrite the baseline only for the target. They drop entries under the
target that are gone from disk and leave entries outside it alone. A directory scan skips
symlinks and anything that is not a regular file.

Exit codes: `0` clean, `1` at least one discrepancy, `2` usage or environment error.

## Store

Location: `$INTEGRITY_DB`, default `./.integrity.db`. One line per file, sorted by path:

```text
#integrity-check v2
<sha256 hex>\t<size bytes>\t<mtime seconds>\t<absolute path>
#hmac-sha256 <hex>          ← only when signing is enabled
```

Each write is atomic, with mode 0600. The store cannot hold a filename that contains a tab, a
newline or invalid UTF-8, so all three versions refuse such a name before they hash anything.
bash needs `iconv` for that check.

## Signing the store

Set `$INTEGRITY_KEY` to a key file, and the tool signs the store with an HMAC-SHA256 over its
contents. If the key file does not exist, the first `init` creates it: 32 random bytes, mode
0600. Every later read checks the signature first, so a tampered baseline aborts instead of
being overwritten. A signed store with no key set is an error, and so is a key set against an
unsigned store.

Signing only helps if the key sits somewhere the attacker can't reach: another host, a
root-owned path, removable media. Keep it outside the monitored tree too, or it shows up as
`Untracked` on every check.

## The `--fast` path

`check --fast` re-hashes only the files whose size or mtime changed since the baseline. That
makes it a weaker check: anything that can write a file can usually also put its size and
mtime back (`touch -r`). I'd use `--fast` for a frequent cron sweep and plain `check` for the
audit that matters.

## Tests and benchmarks

`./test.sh` runs one scenario against each built binary and checks that all three write
byte-identical stores, signature included. `./difftest.sh` runs all three on 50 random trees
and fails, naming the seed, on the first difference in exit code or output. `./bench.sh` writes [BENCHMARKS.md](BENCHMARKS.md)
and needs [hyperfine](https://github.com/sharkdp/hyperfine).

## License

[MIT](LICENSE)
