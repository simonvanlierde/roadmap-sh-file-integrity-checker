# Threat model

What the checker protects, against whom, and where it stops. Line numbers point at the three
implementations: `bash/integrity-check` (sh), `python/integrity-check` (py) and
`rust/src/main.rs` (rs).

## What it protects

- **The content of the watched files.** Each file's SHA-256 goes in the store. Size and
  mtime are stored too, but only `--fast` uses them, to skip the hash (sh:233-238,
  py:101, rs:177-179). Mode, owner, xattrs and timestamps are not compared: a `chmod u+s`
  on an unchanged file is reported as `Unmodified`.
- **The set of files.** A new file is `Untracked`, a deleted one is `Missing`, and both
  count as a discrepancy and exit 1 (sh:286-297, py:236-250, rs:372-393).
- **The store itself, when signing is on.** The signature is one HMAC-SHA256 over the
  raw bytes of every line except the last line, which holds the signature (sh:184,
  py:149-154, rs:262-268). It covers the whole store, not single entries.

## Who the attacker is

The attacker runs as a user who can write the watched files, and maybe the store and its
folder too. They cannot read the key file and are not root. Root on the host, or anyone
who can read the key or change the environment the checker runs in (`INTEGRITY_DB`,
`INTEGRITY_KEY`, `PATH`), is out of scope: they can make the checker say anything.

## What each defence stops

| Defence | Stops | Where |
| --- | --- | --- |
| HMAC over the store | Edited, added or removed entries; a stripped signature (error when a key is set); a changed line ending. Any of these exits 2. | sh:180-191, py:138-155, rs:256-271 |
| Read the store once | Forged entries passing with a genuine signature, by renaming a different store in between two reads. All three verify and parse one copy of the bytes. | sh:154-157, py:163-164, rs:241 |
| Verify before writing | `init`/`update` reads and checks the old store before it rewrites it, so a forged store is never signed. | sh:261, py:214, rs:338 |
| Constant-time compare | Learning the expected signature from timing. bash compares both values hashed under a fresh random nonce. | sh:185-190, py:153, rs:266, rs:332-334 |
| Key kept out of argv | Reading the key from `ps`. bash builds the HMAC from shell builtins and pipes. | sh:116-148 |
| New key: 32 random bytes, mode 0600, create-only | Another user reading a new key, or an existing file being overwritten. | sh:207-210, py:119-125, rs:203-226 |
| Store write: temp file at 0600, create-only, then rename | Other users reading the store; readers seeing a half-written store; a symlink planted at the temp name (the create fails). A failed write exits 2 and removes the temp file. | sh:194-217, py:192-209, rs:295-329 |
| Directory scan takes only regular files, without following symlinks | A symlink in the tree pulling an outside file in under an inside name. An explicit target that is a symlink is followed, as the README says. | sh:85, py:61-64, rs:94-100 |
| py, rs: after `open`, compare device and inode with the scan's stat | A symlink swapped in between the scan and the open: exit 2. A save-by-rename (a new regular file at the same path) is accepted. `O_NOFOLLOW` is not used because it would also refuse the explicit symlink target. | py:82-89, rs:109-118 |

## Out of scope

- **An attacker who can time the check.** Anyone who can write a file can rename the
  original back for the length of the scan and swap their version in again afterwards.
  The inode check accepts that on purpose, because it looks like an editor's save. The
  checker sees the tree only at the moment it runs.
- **The first baseline.** `init` trusts what is on disk. A file that is already bad
  becomes the good hash.
- **Durability after a crash.** No write calls `fsync` before the rename, so a power cut
  can leave an empty or old store on some file systems.
- **Two runs at once.** There is no lock. Two `update` runs race, and the last rename wins.

## Known gaps

1. **Rollback.** The signature has no counter or date, so an attacker who can write the
   store can put back an older store that was signed with the same key. Together with
   an old version of a file, this passes as `Unmodified`, exit 0 (checked by hand:
   baseline, update, then restore both the old file and the old store).
2. **bash: the window between check and open stays.** `stat -L` and `sha256sum` follow
   the path again, so a symlink or another file swapped in after the scan is hashed
   without notice (sh:229, sh:245).
3. **A FIFO swapped in blocks the open** in all three, before any check can run
   (sh:245, py:82, rs:109). The run hangs, which is a denial of service, not a false pass.
4. **A directory swapped for a symlink during the scan** is followed in python and rust:
   `os.walk` and `read_dir` open the new path (py:57, rs:91). The inode check does not
   see it. This only lets the attacker show other content, which an attacker who can
   time the check can do anyway.
5. **The key file is read as is.** No implementation checks its mode or owner when it
   reads it (sh:126-128, py:126-127, rs:227).
