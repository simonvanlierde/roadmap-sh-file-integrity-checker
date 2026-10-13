# File integrity checker

[![CI](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is my solution to the <https://roadmap.sh/projects/file-integrity-checker> exercise. I
wrote it three times: in pure bash, in Python and in Rust. All three read and write the same
file format, so you can swap one binary for another on the same baseline store.

```text
bash/integrity-check                  # bash, uses sha256sum or shasum
python/integrity-check                # python 3, stdlib only
rust/target/release/integrity-check   # cargo build --release --manifest-path rust/Cargo.toml
```

## Usage

All three work the same way:

```console
$ ./bash/integrity-check init ~/notes
Hashes stored successfully. (38 tracked, /Users/you/.integrity.db)

$ ./python/integrity-check check ~/notes/todo.md
/Users/you/notes/todo.md: Modified (hash mismatch)

$ ./rust/target/release/integrity-check check ~/notes
/Users/you/notes/ideas.md: Unmodified
/Users/you/notes/new.md: Untracked
/Users/you/notes/old.md: Missing (file deleted)
/Users/you/notes/todo.md: Modified (hash mismatch)

$ ./bash/integrity-check update ~/notes/todo.md
Hash updated successfully. (38 tracked, /Users/you/.integrity.db)
```

| Command | Effect |
| --- | --- |
| `init <file\|dir>` | Hash every file under the target and write the baseline. |
| `check [--fast] <file\|dir>` | Re-hash and compare against the baseline. |
| `update <file\|dir>` | Re-baseline the target after a legitimate change or deletion. |

`Untracked` means the file exists now but is not in the baseline. `init` and `update` rewrite
the baseline only for the target. They drop entries under the target that are gone from disk,
which clears a `Missing` you have confirmed. They leave entries outside the target alone.

When the tool scans a directory, it skips symlinks and anything that is not a regular file
(FIFOs, sockets, devices). It does follow a target you name yourself.

The store is UTF-8 text with one tab-separated line per file, so it cannot hold a filename
that contains a tab, a newline or invalid UTF-8. All three versions refuse such a name before
they hash anything, with the same message and exit code. bash needs `iconv` for the UTF-8
check, and warns on stderr when it is missing.

Exit codes: `0` clean, `1` at least one discrepancy, `2` usage or environment error. The `1`
lets you use it from cron or CI. All three print the same messages and return the same exit
codes. Only the tail of an OS error differs by runtime (`Permission denied` vs
`Permission denied (os error 13)`).

## Store

Location: `$INTEGRITY_DB`, default `./.integrity.db`. One line per file, sorted by path:

```text
#integrity-check v2
<sha256 hex>\t<size bytes>\t<mtime seconds>\t<absolute path>
#hmac-sha256 <hex>          ← only when signing is enabled
```

Each write is atomic: a temp file, then a rename, with mode 0600. A wrong or missing version
header, or a malformed entry line, aborts with exit 2. The store is plain text, so `diff`,
`grep` and `git` all work on it. `./test.sh` checks that all three implementations write
byte-identical stores, signature included.

## Signing the store

Set `$INTEGRITY_KEY` to a key file, and the tool signs the store with an HMAC-SHA256 over its
contents:

```console
$ INTEGRITY_DB=/var/lib/integrity.db INTEGRITY_KEY=~/.integrity.key ./bash/integrity-check init /var/log
Generated signing key /Users/you/.integrity.key. Keep it off the monitored host.
Hashes stored successfully. (412 tracked, /var/lib/integrity.db)

$ INTEGRITY_DB=/var/lib/integrity.db INTEGRITY_KEY=~/.integrity.key ./bash/integrity-check check /var/log
error: store signature mismatch: the baseline itself was tampered with
```

If the key file does not exist, the first `init` creates it: 32 random bytes, mode 0600.
Every later read checks the signature first. That includes the read `init` and `update` do
before they rewrite the store, so a tampered baseline aborts instead of being overwritten. A
signed store with no key set is an error, and so is a key set against an unsigned store.

Signing only helps if the key sits somewhere the attacker can't reach: another host, a
root-owned path, removable media. Keep it outside the monitored tree too, or it shows up as
`Untracked` on every check.

## The `--fast` path

`check --fast` re-hashes only the files whose size or mtime changed since the baseline. For
the rest, it trusts the stored hash.

That makes it a weaker check. Anything that can write a file can usually also put its size
and mtime back afterwards (`touch -r`), and `--fast` will then call that file unmodified. I'd
use `--fast` for a frequent cron sweep and plain `check` for the audit that matters. Every run
records size and mtime, so you can switch between the two modes without a re-init.

## Tests

```console
$ ./test.sh
ok: bash/integrity-check
ok: python/integrity-check
ok: rust/target/release/integrity-check
ok: implementations agree, signatures included
```

The script runs one scenario against each binary. It covers tamper detection, pruning, error
paths, whitespace filenames, symlink and FIFO skipping, the `--fast` blind spot, key
permissions and tampering with a signed store.

It then compares the stores the three wrote. bash's HMAC is a hand-rolled RFC 2104 version,
built from `sha256sum` and shell arithmetic. The comparison requires it to match Python's
`hmac` module and Rust's `hmac` crate byte for byte. The script skips any implementation
that is not built.

## Implementation notes

**bash**: `find` for the walk, one batched `stat`, `xargs -P` over `sha256sum` for the
hashing, `awk` to match store entries against files on disk. I built the HMAC from builtins
and pipes, so the key never appears in `argv`, where `ps` could read it.

**python**: stdlib `hashlib`, `hmac` and `os.walk`, 1 MB read chunks. It uses threads only
above 16 MB of work. Below that, handing off the GIL (Python's global interpreter lock) costs
more than it saves.

**rust**: `std::fs` for the walk, `sha2` + `hmac` for the crypto, `BTreeMap` for the join,
`std::thread::scope` with a shared work cursor for parallel hashing. The `asm` feature on
`sha2` picks the hardware SHA-2 path, which is worth ~5x on large files. No `clap`, no
`walkdir`, no `rayon`.

## Benchmarks

The full numbers and method are in [BENCHMARKS.md](BENCHMARKS.md). Run `./bench.sh` to
regenerate them (it needs [hyperfine](https://github.com/sharkdp/hyperfine)). On an M1 Mac,
mean of 25 runs:

| Workload | bash | python | rust |
| --- | ---: | ---: | ---: |
| `init` 500 files × 4 KB | 164 ms | 63 ms | 23 ms |
| `check --fast` 500 files × 4 KB, 10% modified | 104 ms | 52 ms | 5 ms |
| `init` 1 file × 256 MB | 356 ms | 200 ms | 187 ms |
| `check --fast` 1 file × 256 MB, unchanged | 77 ms | 38 ms | 3 ms |
| `check --fast` 10 files, 50,010-entry store | 1129 ms | 81 ms | 12 ms |

Many small files mostly measures process start-up: bash pays for forks the others don't. One
large file mostly measures I/O, because python and rust end up in the same hardware SHA-2
instructions. The last two rows isolate store size, and that is where the three spread
furthest apart. Each extra store entry costs ~21 µs in bash, 0.9 µs in python and 0.2 µs in
rust.

## License

[MIT](LICENSE)
