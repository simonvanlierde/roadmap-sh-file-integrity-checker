# File integrity checker

[![CI](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/simonvanlierde/roadmap-sh-file-integrity-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

My solution to the <https://roadmap.sh/projects/file-integrity-checker> exercise, implemented
three times (pure bash, Python, and Rust) against one shared on-disk format, so the three
binaries are interchangeable on the same baseline store.

```text
bash/integrity-check                  # bash, uses sha256sum or shasum
python/integrity-check                # python 3, stdlib only
rust/target/release/integrity-check   # cargo build --release --manifest-path rust/Cargo.toml
```

## Usage

Identical for all three:

```console
$ ./bash/integrity-check init /var/log
Hashes stored successfully. (412 tracked, /Users/you/.integrity.db)

$ ./python/integrity-check check /var/log/syslog
/var/log/syslog: Modified (hash mismatch)

$ ./rust/target/release/integrity-check check /var/log
/var/log/auth.log: Unmodified
/var/log/new.log: Untracked
/var/log/old.log: Missing (file deleted)
/var/log/syslog: Modified (hash mismatch)

$ ./bash/integrity-check update /var/log/syslog
Hash updated successfully. (412 tracked, /Users/you/.integrity.db)
```

| Command | Effect |
| --- | --- |
| `init <file\|dir>` | Hash every file under the target and write the baseline. |
| `check [--fast] <file\|dir>` | Re-hash and compare against the baseline. |
| `update <file\|dir>` | Re-baseline the target after a legitimate change or deletion. |

`Untracked` means present now but not in the baseline. `init` and `update` re-baseline only
the target: entries under it that are gone from disk are dropped (which clears a confirmed
`Missing`), entries outside it are untouched.

Symlinks and non-regular files (FIFOs, sockets, devices) inside a scanned directory are
skipped; an explicit target is followed.

Filenames containing a tab, a newline, or invalid UTF-8 are rejected before anything is
hashed (because the line-based, tab-separated, UTF-8 store cannot hold them) with the same message
and exit code in all three. bash needs `iconv` for the UTF-8 check and warns on stderr when
it is missing.

Exit codes: `0` clean, `1` at least one discrepancy, `2` usage or environment error. The `1`
makes it usable from cron or CI. Messages and exit codes are identical across the three; only
the tail of an OS error (`Permission denied` vs `Permission denied (os error 13)`) varies by
runtime.

## Store

Location: `$INTEGRITY_DB`, default `./.integrity.db`. One line per file, sorted by path:

```text
#integrity-check v2
<sha256 hex>\t<size bytes>\t<mtime seconds>\t<absolute path>
#hmac-sha256 <hex>          ← only when signing is enabled
```

Written atomically (temp file + rename, mode 0600). A wrong or missing version header, or a
malformed entry line, aborts with exit 2. Plain text: `diff`, `grep` and `git` all work on
it, and `./test.sh` asserts all three implementations produce byte-identical stores,
signature included.

## Signing the store

Set `$INTEGRITY_KEY` to a key file and the store is signed with HMAC-SHA256 over its contents:

```console
$ INTEGRITY_DB=/var/lib/integrity.db INTEGRITY_KEY=~/.integrity.key ./bash/integrity-check init /var/log
Generated signing key /Users/you/.integrity.key. Keep it off the monitored host.
Hashes stored successfully. (412 tracked, /var/lib/integrity.db)

$ INTEGRITY_DB=/var/lib/integrity.db INTEGRITY_KEY=~/.integrity.key ./bash/integrity-check check /var/log
error: store signature mismatch: the baseline itself was tampered with
```

The key is generated on first `init` if the file does not exist (32 random bytes, mode 0600).
Every later read verifies the signature first (including the read `init` and `update` do
before rewriting) so a tampered baseline aborts instead of being overwritten. A signed store
with no key set, or a key set against an unsigned store, is an error.

Signing only helps if the key is somewhere the attacker is not (another host, a root-owned
path, removable media) and outside the monitored tree, or it shows up as `Untracked` on
every check.

## The `--fast` path

`check --fast` re-hashes only files whose size or mtime changed since the baseline, and
trusts the stored hash for the rest.

It is a weaker check: anything that can write a file can usually also restore its size and
mtime afterwards (`touch -r`), and `--fast` will call that file unmodified. Use `--fast` for
a frequent cron sweep, plain `check` for the audit that matters. Size and mtime are recorded
on every run, so switching between the two modes needs no re-init.

## Tests

```console
$ ./test.sh
ok: bash/integrity-check
ok: python/integrity-check
ok: rust/target/release/integrity-check
ok: implementations agree, signatures included
```

One scenario replayed against each binary (tamper detection, pruning, error paths,
whitespace filenames, symlink/FIFO skipping, the `--fast` blind spot, key permissions,
signed-store tampering) plus a cross-implementation store comparison that requires bash's
hand-rolled RFC 2104 HMAC (built from `sha256sum` and shell arithmetic) to match Python's
`hmac` module and Rust's `hmac` crate byte for byte. Implementations that are not built are
skipped.

## Implementation notes

**bash**: `find` for the walk, one batched `stat`, `xargs -P` over `sha256sum` for the
hashing, `awk` for the store/tree joins. The HMAC is assembled from builtins and pipes so the
key never appears in `argv` where `ps` could read it.

**python**: stdlib `hashlib`, `hmac` and `os.walk`, 1 MB read chunks, threads only above
16 MB of work; below that the GIL handoff costs more than it saves.

**rust**: `std::fs` for the walk, `sha2` + `hmac` for the crypto, `BTreeMap` for the join,
`std::thread::scope` with a shared work cursor for parallel hashing. The `asm` feature on
`sha2` selects the hardware SHA-2 path, worth ~5x on large files. No `clap`, no `walkdir`,
no `rayon`.

## Benchmarks

Full numbers and methodology in [BENCHMARKS.md](BENCHMARKS.md); regenerate with `./bench.sh`
(needs [hyperfine](https://github.com/sharkdp/hyperfine)). On an M1 Mac, mean of 25 runs:

| Workload | bash | python | rust |
| --- | ---: | ---: | ---: |
| `init` 500 files × 4 KB | 164 ms | 63 ms | 23 ms |
| `check --fast` 500 files × 4 KB, 10% modified | 104 ms | 52 ms | 5 ms |
| `init` 1 file × 256 MB | 356 ms | 200 ms | 187 ms |
| `check --fast` 1 file × 256 MB, unchanged | 77 ms | 38 ms | 3 ms |
| `check --fast` 10 files, 50,010-entry store | 1129 ms | 81 ms | 12 ms |

Many small files is a process-spawn benchmark: bash pays for forks the others do not. One
large file is an I/O benchmark: python and rust end up in the same hardware SHA-2
instructions. The last two rows isolate store size, where the three spread furthest apart:
an extra store entry costs ~21 µs in bash, 0.9 µs in python and 0.2 µs in rust.

## License

[MIT](LICENSE)
