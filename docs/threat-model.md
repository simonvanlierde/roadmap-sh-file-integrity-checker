# Threat model

What the checker protects, against whom, and where it stops. The "Where" column names the
function in each version: sh is `bash/integrity-check`, py is `python/integrity-check` and rs
is `rust/src/main.rs`.

## What it protects

- **The content of the watched files.** Each file's SHA-256 goes in the store. Size and
  mtime are stored too, but only `--fast` uses them, to skip the hash (`scan` in all three).
  Mode, owner, xattrs and timestamps are not compared: a `chmod u+s` on an unchanged file is
  reported as `Unmodified`.
- **The set of files.** A new file is `Untracked`, a deleted one is `Missing`, and both
  count as a discrepancy and exit 1 (`cmd_check`).
- **The store itself, when signing is on.** The signature is one HMAC-SHA256 over the raw
  bytes of every line except the last one, which holds the signature (sh `db_entries`, py
  `verified`, rs `load_text`). It covers the whole store, not single entries.

## Who the attacker is

The attacker runs as a user who can write the watched files, and maybe the store and its
folder too. They cannot read the key file and are not root. Root on the host, or anyone who
can read the key or change the environment the checker runs in (`INTEGRITY_DB`,
`INTEGRITY_KEY`, `PATH`), is out of scope: they can make the checker say anything.

## What each defence stops

| Defence | Stops | Where |
| --- | --- | --- |
| HMAC over the store | Edited, added or removed entries; a stripped signature (an error when a key is set); a changed line ending. Each exits 2. | sh `db_entries`, py `verified`, rs `load_text` |
| Read the store once | Forged entries passing with a genuine signature, by renaming a different store in between two reads. All three verify and parse one copy of the bytes. | sh `db_entries`, py `load`, rs `load_text` |
| Verify before writing | `init` and `update` read and check the old store before they rewrite it, so a forged store is never signed. | `cmd_store` |
| Constant-time compare | Learning the expected signature from timing. bash compares both values hashed under a fresh random nonce. | sh `db_entries`, py `verified`, rs `subtle_eq` |
| Key kept out of argv | Reading the key from `ps`. bash builds the HMAC from shell builtins and pipes. | sh `hmac_file` |
| New key: 32 random bytes, mode 0600, create-only; an empty key file is refused | Another user reading a new key, an existing file being overwritten, and signing with a key anyone can reproduce. | sh `write_db` and `need_key`, py and rs `read_key` |
| Store write: temp file at 0600, create-only, then rename | Other users reading the store; readers seeing a half-written store; a symlink planted at the temp name (the create fails). A failed write exits 2 and removes the temp file. | sh `write_db`, py and rs `save` |
| A directory scan takes only regular files and does not follow symlinks | A symlink in the tree pulling an outside file in under an inside name. An explicit target that is a symlink is followed, as the README says. | sh `list`, py `files`, rs `collect` |
| py, rs: after `open`, compare device and inode with the scan's stat | A symlink swapped in between the scan and the open: exit 2. A save-by-rename (a new regular file at the same path) is accepted. `O_NOFOLLOW` is not used, because it would also refuse the explicit symlink target. | py and rs `sha256` |

## Out of scope

- **An attacker who can time the check.** Anyone who can write a file can rename the
  original back for the length of the scan and swap their version in again afterwards. The
  inode check accepts that on purpose, because it looks like an editor's save. The checker
  sees the tree only at the moment it runs.
- **The first baseline.** `init` trusts what is on disk. A file that is already bad becomes
  the good hash.
- **Durability after a crash.** No write calls `fsync` before the rename, so a power cut can
  leave an empty or old store on some file systems.
- **Two runs at once.** There is no lock. Two `update` runs race, and the last rename wins.

## Known gaps

1. **Rollback.** The signature has no counter or date, so an attacker who can write the
   store can put back an older store signed with the same key. Together with an old
   version of a file, this passes as `Unmodified`, exit 0.
2. **bash: the window between check and open stays.** `stat -L` and `sha256sum` follow the
   path again, so a symlink or another file swapped in after the scan is hashed without
   notice (sh `scan`).
3. **A FIFO swapped in blocks the open** in all three, before any check can run (sh `scan`,
   py and rs `sha256`). The run hangs, which is a denial of service, not a false pass.
4. **A directory swapped for a symlink during the scan** is followed in python and rust:
   `os.walk` and `read_dir` open the new path (py `files`, rs `collect`). The inode check
   does not see it. This only lets the attacker show other content, which an attacker who
   can time the check can do anyway.
5. **The key file's mode and owner are not checked** when it is read (sh `need_key`, py and
   rs `read_key`).
