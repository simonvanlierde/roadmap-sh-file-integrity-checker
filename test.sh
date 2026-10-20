#!/usr/bin/env bash
# Same scenario against all three implementations. Fails loudly on any mismatch.
set -euo pipefail
cd "$(dirname "$0")"

# INTEGRITY_IMPLS replaces the list, for example with the binary `cargo test` just built.
read -r -a IMPLS <<<"${INTEGRITY_IMPLS:-bash/integrity-check python/integrity-check rust/target/release/integrity-check}"
path_of() { case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$PWD/$1" ;; esac }

# macOS sets TMPDIR with a trailing slash; collapse it like the implementations do, or
# the literal path comparisons below compare two spellings.
TMPDIR=${TMPDIR:-/tmp}
while [ "$TMPDIR" != "${TMPDIR//\/\///}" ]; do TMPDIR=${TMPDIR//\/\///}; done
[ "$TMPDIR" = / ] || TMPDIR=${TMPDIR%/}
export TMPDIR

# Prints the failing assertion's line: the caller's when called from a helper.
fail() { # <message...>, always inside the per-implementation loop
  local n=${BASH_LINENO[1]:-0}
  echo "FAIL [$impl:$((n ? n : BASH_LINENO[0]))] $*" >&2
  exit 1
}
run() { # <expected exit code> <cmd...> -> sets OUT
  local want=$1
  shift
  OUT=$("$@" 2>&1) && CODE=0 || CODE=$?
  [ "$CODE" = "$want" ] || fail "exit $CODE, wanted $want, from '$*': $OUT"
}
assert() { # <expected substring> [haystack, defaults to OUT]
  case ${2-$OUT} in
  *"$1"*) ;;
  *) fail "expected '$1' in: ${2-$OUT}" ;;
  esac
}
refute() { # <forbidden substring> [haystack, defaults to OUT]
  case ${2-$OUT} in *"$1"*) fail "unexpected '$1' in: ${2-$OUT}" ;; esac
}

BUILT=()
for impl in "${IMPLS[@]}"; do
  if [ -x "$impl" ]; then BUILT+=("$impl"); else echo "skip: $impl not built"; fi
done
[ ${#BUILT[@]} -gt 0 ] || {
  echo "FAIL: no implementations built: nothing was tested" >&2
  exit 1
}

# ext4 stores filenames that are not valid UTF-8, APFS refuses them outright. Probe the
# filesystem rather than the OS, so the case below runs wherever it can. The 2> comes
# first: the shell reports a failed redirection before a later 2> would silence it.
probe=$(mktemp -d "$TMPDIR/integrity.XXXXXX")
if printf 'x' 2>/dev/null >"$probe/$(printf 'bad\xffname').log"; then
  BADNAME=1
else
  BADNAME=
  echo "skip: this filesystem refuses non-UTF-8 filenames"
fi
rm -rf "$probe"

for impl in "${BUILT[@]}"; do
  tmp=$(mktemp -d "$TMPDIR/integrity.XXXXXX")
  export INTEGRITY_DB="$tmp/.integrity.db"
  unset INTEGRITY_KEY
  cli=$(path_of "$impl")
  printf 'one\n' >"$tmp/a.log"
  printf 'two\n' >"$tmp/b.log"
  mkdir "$tmp/sub" && printf 'three\n' >"$tmp/sub/c.log"

  run 0 "$cli" init "$tmp"
  assert "Hashes stored successfully"
  run 0 "$cli" check "$tmp"
  assert "a.log: Unmodified"
  assert "sub/c.log: Unmodified"

  printf 'tampered\n' >"$tmp/a.log"
  run 1 "$cli" check "$tmp"
  assert "a.log: Modified (hash mismatch)"
  assert "b.log: Unmodified"

  run 1 "$cli" check "$tmp/a.log"
  assert "a.log: Modified (hash mismatch)"
  run 0 "$cli" update "$tmp/a.log"
  assert "Hash updated successfully"
  run 0 "$cli" check "$tmp"
  assert "a.log: Unmodified"

  printf 'new\n' >"$tmp/d.log"
  run 1 "$cli" check "$tmp"
  assert "d.log: Untracked"

  rm "$tmp/b.log"
  run 1 "$cli" check "$tmp"
  assert "b.log: Missing (file deleted)"

  run 2 env INTEGRITY_DB="$tmp/nope.db" "$cli" check "$tmp"
  assert "no baseline"
  run 2 "$cli" check "$tmp/ghost.log"
  assert "no such file"

  # --fast trusts size+mtime: an edit preserving both slips past it; full check catches it
  rm -f "$INTEGRITY_DB"
  printf 'one\n' >"$tmp/a.log"
  run 0 "$cli" init "$tmp"
  cp -p "$tmp/a.log" "$tmp.ref"
  printf 'ONE\n' >"$tmp/a.log" # same size as 'one\n'
  touch -r "$tmp.ref" "$tmp/a.log"
  run 0 "$cli" check --fast "$tmp"
  assert "a.log: Unmodified"
  run 1 "$cli" check "$tmp"
  assert "a.log: Modified (hash mismatch)"
  # a real edit changes mtime, so --fast does catch that one
  printf 'much longer content\n' >"$tmp/a.log"
  run 1 "$cli" check --fast "$tmp"
  assert "a.log: Modified (hash mismatch)"
  run 2 "$cli" init --fast "$tmp"
  assert "usage"

  # init/update on a missing target is an error
  run 2 "$cli" init "$tmp/ghost"
  assert "no such file"

  # whitespace filenames survive the pipeline, runs of spaces included
  printf 'sp\n' >"$tmp/two  spaces.log"
  printf 'sp\n' >"$tmp/trail .log"
  run 0 "$cli" update "$tmp"
  printf 'SP\n' >"$tmp/two  spaces.log"
  run 1 "$cli" check "$tmp"
  assert "two  spaces.log: Modified (hash mismatch)"
  run 0 "$cli" update "$tmp"

  # a deleted tree reports Missing, not Untracked, and never pulls in other dirs
  mkdir "$tmp/gone" && printf 'g\n' >"$tmp/gone/g.log"
  run 0 "$cli" update "$tmp/gone"
  rm "$tmp/gone/g.log"
  run 1 "$cli" check "$tmp/gone"
  assert "gone/g.log: Missing (file deleted)"
  refute "a.log" # unrelated entries must not leak in
  # re-baselining the target prunes the deleted entry instead of reporting it forever
  before=$(grep -cv '^#' "$INTEGRITY_DB")
  run 0 "$cli" update "$tmp/gone"
  ! grep -qF "$tmp/gone/g.log" "$INTEGRITY_DB" || fail "prune: deleted entry survived the re-baseline"
  [ "$(grep -cv '^#' "$INTEGRITY_DB")" = "$((before - 1))" ] ||
    fail "prune: dropped more than the one deleted entry"
  run 0 "$cli" check "$tmp/gone"
  rmdir "$tmp/gone"

  # init of an empty dir must not drop the rest of the baseline
  before=$(grep -cv '^#' "$INTEGRITY_DB")
  mkdir "$tmp/empty"
  run 0 "$cli" init "$tmp/empty"
  [ "$(grep -cv '^#' "$INTEGRITY_DB")" = "$before" ] || fail "empty-dir init changed the baseline"
  run 0 "$cli" check "$tmp/empty"
  [ -z "$OUT" ] || fail "empty-check: expected no output, got: $OUT"
  rmdir "$tmp/empty"

  # symlinks and fifos are skipped, not followed/hung on
  ln -s a.log "$tmp/link.log"
  mkfifo "$tmp/pipe"
  run 0 "$cli" update "$tmp"
  ! grep -q 'link\.log\|pipe' "$INTEGRITY_DB" || fail "symlink or fifo was tracked"
  # a fifo named outright is one error, not a pile of them
  run 2 "$cli" check "$tmp/pipe"
  assert "not a regular file"
  [ "$(printf '%s\n' "$OUT" | wc -l)" -eq 1 ] || fail "fifo-target: expected one error line, got: $OUT"
  rm "$tmp/link.log" "$tmp/pipe"

  # two independent roots share one store without clobbering (README merge claim)
  other=$(mktemp -d "$TMPDIR/integrity.XXXXXX")
  printf 'o\n' >"$other/o.log"
  run 0 "$cli" init "$other"
  run 0 "$cli" check "$tmp"
  run 0 "$cli" check "$other"
  run 0 "$cli" check --fast "$other"
  assert "o.log: Unmodified"
  rm -rf "$other"

  # malformed store lines and unknown versions fail loudly
  cp "$INTEGRITY_DB" "$tmp/db.bak"
  printf 'garbage line\n' >>"$INTEGRITY_DB"
  run 2 "$cli" check "$tmp"
  assert "malformed store line"
  # check keeps only the entries under its target, but still validates the rest
  cp "$tmp/db.bak" "$INTEGRITY_DB"
  printf '%064d\t12x\t1\t/elsewhere/f.log\n' 0 >>"$INTEGRITY_DB"
  run 2 "$cli" check --fast "$tmp"
  assert "malformed store line"
  sed '1s/v2/v99/' "$tmp/db.bak" >"$INTEGRITY_DB"
  run 2 "$cli" check "$tmp"
  assert "unsupported store"
  cp "$tmp/db.bak" "$INTEGRITY_DB" && rm "$tmp/db.bak"

  # default store path is ./.integrity.db in the CWD
  rm -f "$tmp/.integrity.db"
  (cd "$tmp" && env -u INTEGRITY_DB "$cli" init a.log >/dev/null && [ -f .integrity.db ]) ||
    fail "default INTEGRITY_DB path"
  rm -f "$tmp/.integrity.db"

  # trailing slash must not change the verdict; re-init since the case above removed the baseline
  run 0 "$cli" init "$tmp"
  run 0 "$cli" check "$tmp/"
  assert "a.log: Unmodified"

  # "//", "/./" and "/../" in the target collapse to one canonical store key
  run 0 env INTEGRITY_DB="$tmp/messy.db" "$cli" init "$tmp//sub/./../sub/"
  [ "$(grep -cF "$tmp/sub/c.log" "$tmp/messy.db")" = 1 ] ||
    fail "messy-path: not canonicalized: $(grep -v '^#' "$tmp/messy.db")"
  rm -f "$tmp/messy.db"

  # a store path that is a directory is an environment error, not silent success
  mkdir "$tmp/dbdir"
  run 2 env INTEGRITY_DB="$tmp/dbdir" "$cli" init "$tmp/a.log"
  assert "error"
  rmdir "$tmp/dbdir" # must be empty: nothing may be written inside the store directory
  # all three name the temp store "<db>.<pid>.tmp"
  residue=$(find "$tmp" -maxdepth 1 -name '*.tmp')
  [ -z "$residue" ] || fail "dir-store: temp file residue: $residue"

  # pre-1970 mtimes round-trip (skip if touch cannot set one)
  if touch -t 196901010000 "$tmp/old.log" 2>/dev/null; then
    run 0 "$cli" update "$tmp"
    run 0 "$cli" check "$tmp"
    assert "old.log: Unmodified"
    rm "$tmp/old.log"
    run 0 "$cli" update "$tmp"
  fi

  # signed store
  export INTEGRITY_KEY="$tmp.key"
  rm -f "$INTEGRITY_DB"
  run 0 "$cli" init "$tmp"
  assert "Generated signing key"
  # GNU first: its -f means --file-system, so it prints a block to stdout *and* exits
  # nonzero, and the substitution would capture that along with the fallback's answer.
  # BSD's -c is simply an illegal option, so it fails silently.
  [ "$(stat -c '%a' "$INTEGRITY_KEY" 2>/dev/null || stat -f '%Lp' "$INTEGRITY_KEY")" = 600 ] ||
    fail "key file is not 0600"
  grep -q '^#hmac-sha256 ' "$INTEGRITY_DB" || fail "store is unsigned"
  run 0 "$cli" check "$tmp"
  run 2 env INTEGRITY_KEY="$tmp/gone" "$cli" check "$tmp"
  assert "key file not found"
  refute "tampered" # a key problem must not be reported as a tampered baseline
  # an empty key signs nothing: refuse it rather than sign with it or drop the signature
  : >"$tmp.empty"
  run 2 env INTEGRITY_KEY="$tmp.empty" INTEGRITY_DB="$tmp/ek.db" "$cli" init "$tmp/a.log"
  assert "key file is empty"
  [ ! -e "$tmp/ek.db" ] || fail "stored a baseline with an empty key"
  rm "$tmp.empty"
  # a key other users can read or replace is refused, as ssh refuses such a private key
  cp "$INTEGRITY_KEY" "$tmp.open"
  chmod 644 "$tmp.open"
  run 2 env INTEGRITY_KEY="$tmp.open" "$cli" check "$tmp"
  assert "open to other users"
  chmod 620 "$tmp.open"
  run 2 env INTEGRITY_KEY="$tmp.open" "$cli" check "$tmp"
  assert "open to other users"
  rm "$tmp.open"
  run 2 env -u INTEGRITY_KEY "$cli" check "$tmp"
  assert "store is signed"
  # an unreadable key must abort, not sign a fresh store with nothing
  chmod 000 "$INTEGRITY_KEY"
  run 2 env INTEGRITY_DB="$tmp/nokey.db" "$cli" init "$tmp/a.log"
  [ ! -e "$tmp/nokey.db" ] || fail "stored a baseline despite an unreadable key"
  chmod 600 "$INTEGRITY_KEY"
  # a key that cannot be created is an environment error (2), not a discrepancy (1)
  run 2 env INTEGRITY_KEY="$tmp/nodir/key" INTEGRITY_DB="$tmp/nokey.db" "$cli" init "$tmp/a.log"
  [ ! -e "$tmp/nokey.db" ] || fail "stored a baseline without a key"
  # rewriting a stored hash by hand must be caught even though the file is untouched
  sed 's/^[0-9a-f]\{64\}/0000000000000000000000000000000000000000000000000000000000000000/' \
    "$INTEGRITY_DB" >"$INTEGRITY_DB.tmp" && mv "$INTEGRITY_DB.tmp" "$INTEGRITY_DB"
  run 2 "$cli" check "$tmp"
  assert "signature mismatch"
  run 2 "$cli" init "$tmp"
  assert "signature mismatch"

  # An older signed store put back together with an older file is refused: each signed
  # write records the store's signature next to the key, and each read checks it.
  export INTEGRITY_KEY="$tmp.rkey" INTEGRITY_DB="$tmp/roll.db"
  printf 'v1\n' >"$tmp/r.log"
  run 0 "$cli" init "$tmp/r.log"
  cp "$INTEGRITY_DB" "$tmp/roll.old"
  cp -p "$tmp/r.log" "$tmp/r.old"
  printf 'v2\n' >"$tmp/r.log"
  run 0 "$cli" update "$tmp/r.log"
  cp "$tmp/roll.old" "$INTEGRITY_DB"
  cp -p "$tmp/r.old" "$tmp/r.log"
  run 2 "$cli" check "$tmp/r.log"
  assert "not the latest one recorded"
  run 2 "$cli" update "$tmp/r.log"
  assert "not the latest one recorded"
  # one key signs several stores without either looking rolled back
  run 0 env INTEGRITY_DB="$tmp/roll2.db" "$cli" init "$tmp/a.log"
  run 0 env INTEGRITY_DB="$tmp/roll3.db" "$cli" init "$tmp/a.log"
  run 0 env INTEGRITY_DB="$tmp/roll2.db" "$cli" check "$tmp/a.log"
  # a record that cannot be written is a warning, not a failure (root ignores the mode)
  if [ "$(id -u)" != 0 ]; then
    mkdir "$tmp/ro"
    (umask 077 && head -c 32 /dev/urandom >"$tmp/ro/key")
    chmod 500 "$tmp/ro"
    run 0 env INTEGRITY_KEY="$tmp/ro/key" INTEGRITY_DB="$tmp/ro.db" "$cli" init "$tmp/a.log"
    assert "warning: cannot record the store signature"
    run 0 env INTEGRITY_KEY="$tmp/ro/key" INTEGRITY_DB="$tmp/ro.db" "$cli" check "$tmp/a.log"
    chmod 700 "$tmp/ro"
  fi
  unset INTEGRITY_KEY

  # --- cases where the three must agree -----------------------------------------
  export INTEGRITY_DB="$tmp/parity.db" # fresh: the store above is deliberately tampered

  # tab/newline filenames are refused by name, before hashing
  bad=$tmp/bad
  mkdir "$bad"
  printf 'x' >"$bad/$(printf 'has\ttab')"
  run 2 "$cli" init "$bad"
  assert "unsupported filename (tab or newline)"
  rm -f "$bad"/*
  printf 'x' >"$bad/$(printf 'has\nnewline')"
  run 2 "$cli" init "$bad"
  assert "unsupported filename (tab or newline)"

  # 0x0B ends a line for python's splitlines() but not for rust or awk, so python must
  # not split on it, or it rejects a store the other two just wrote
  vt=$tmp/vt
  mkdir "$vt"
  printf 'x' >"$vt/$(printf 'a\vb').log"
  run 0 "$cli" init "$vt"
  run 0 "$cli" check "$vt"
  assert "Unmodified"

  # a non-UTF-8 filename is refused with one message by all three, rather than silently
  # tracked by some of them
  if [ -n "$BADNAME" ]; then
    nb=$tmp/nb
    mkdir "$nb"
    printf 'x' >"$nb/$(printf 'bad\xffname').log"
    run 2 "$cli" init "$nb"
    assert "non-UTF-8 filename unsupported"
  fi

  # The store must not track itself even when its name holds glob metacharacters; only
  # the second init can catch this, since on the first the store does not exist yet.
  glob=$tmp/glob
  mkdir "$glob"
  printf 'x' >"$glob/a.log"
  INTEGRITY_DB="$glob/log[1].db" "$cli" init "$glob" >/dev/null
  INTEGRITY_DB="$glob/log[1].db" "$cli" init "$glob" >/dev/null
  [ "$(grep -cv '^#' "$glob/log[1].db")" = 1 ] || fail "store tracked itself: $(cat "$glob/log[1].db")"
  # nor when the store is the target itself
  INTEGRITY_DB="$glob/log[1].db" "$cli" init "$glob/log[1].db" >/dev/null
  [ "$(grep -cv '^#' "$glob/log[1].db")" = 1 ] || fail "store tracked itself: $(cat "$glob/log[1].db")"
  # JOBS in the environment is someone else's setting
  run 0 env JOBS=auto INTEGRITY_DB="$glob/log[1].db" "$cli" init "$glob"

  # the store-level cases below need a plain filename: against $vt they would exit 2
  # for the 0x0B reason and test nothing
  plain=$tmp/plain
  mkdir "$plain"
  printf 'x' >"$plain/p.log"

  # a non-UTF-8 store is refused with one message by all three
  printf '#integrity-check v2\n%064d\t1\t1\t/tmp/bad\xffname.log\n' 0 >"$INTEGRITY_DB"
  run 2 "$cli" check "$plain"
  assert "store is not valid UTF-8"

  # size and mtime are plain ASCII digits (mtime may be negative); python's int() and
  # rust's parse() alone accept some of these
  for sm in ' 12	1' '+5	1' '1_0	1' '-1	1' '١٢	1' '	1' '1	 1' '1	+1' '1	1_0' '1	--1' '1	'; do
    printf '#integrity-check v2\n%064d\t%s\t%s\n' 0 "$sm" "$plain/p.log" >"$INTEGRITY_DB"
    run 2 "$cli" check "$plain"
    assert "malformed store line"
  done

  # size fits a u64 and mtime an i64, as in rust; bash and python check the length too
  for sm in '18446744073709551616	1' '99999999999999999999	1' '1	9223372036854775808' \
    '1	-9223372036854775809' '0018446744073709551616	1'; do
    printf '#integrity-check v2\n%064d\t%s\t%s\n' 0 "$sm" "$plain/p.log" >"$INTEGRITY_DB"
    run 2 "$cli" check "$plain"
    assert "malformed store line"
  done
  # the bounds themselves still parse, leading zeros too: the entry is only stale
  for sm in '18446744073709551615	1' '1	9223372036854775807' '1	-9223372036854775808' \
    '0018446744073709551615	-0009223372036854775808'; do
    printf '#integrity-check v2\n%064d\t%s\t%s\n' 0 "$sm" "$plain/p.log" >"$INTEGRITY_DB"
    run 1 "$cli" check "$plain"
    assert "p.log: Modified"
  done

  # A valid store whose byte 1023 starts a 3-byte character: macOS iconv, reading 1024
  # bytes at a time, refused such a store (bash exit 2, no output).
  rm -f "$INTEGRITY_DB"
  run 0 "$cli" init "$plain"
  pad=$((1023 - $(wc -c <"$INTEGRITY_DB") - 70)) # 70: hash, tab, 0, tab, 0, tab, slash
  printf '%064d\t0\t0\t/%s日.log\n' 0 "$(printf "%${pad}s" '' | tr ' ' x)" >>"$INTEGRITY_DB"
  [ "$(od -An -tx1 -j1023 -N1 "$INTEGRITY_DB" | tr -d ' ')" = e6 ] || fail "store layout off"
  run 0 "$cli" check "$plain"
  assert "p.log: Unmodified"

  # the signature covers the store's raw bytes: rewriting line endings under it must fail
  rm -f "$INTEGRITY_DB"
  export INTEGRITY_KEY="$tmp.key2"
  run 0 "$cli" init "$plain"
  sed $'s/$/\r/' "$INTEGRITY_DB" >"$tmp.crlf"
  mv "$tmp.crlf" "$INTEGRITY_DB"
  run 2 "$cli" check "$plain"
  assert "signature mismatch"
  # a non-ASCII signature is a mismatch too, not a crash (python's compare_digest on str)
  rm -f "$INTEGRITY_DB"
  run 0 "$cli" init "$plain"
  sed '$s/^\(#hmac-sha256 \).*/\1héllo/' "$INTEGRITY_DB" >"$tmp.sig"
  mv "$tmp.sig" "$INTEGRITY_DB"
  run 2 "$cli" check "$plain"
  assert "signature mismatch"
  unset INTEGRITY_KEY
  # An empty signature line carries no signature: the store is unsigned, so it passes
  # without a key and is refused as unsigned with one.
  rm -f "$INTEGRITY_DB"
  run 0 "$cli" init "$plain"
  printf '#hmac-sha256 \n' >>"$INTEGRITY_DB"
  run 0 "$cli" check "$plain"
  assert "p.log: Unmodified"
  run 2 env INTEGRITY_KEY="$tmp.key2" "$cli" check "$plain"
  assert "store is unsigned"

  # bash without perl skips the UTF-8 check with a warning instead of aborting.
  # perl shares /usr/bin with the rest, so PATH gets a dir of links to everything else.
  if [ "$impl" = bash/integrity-check ]; then
    noperl=$tmp/noperl
    mkdir "$noperl"
    for t in bash awk cat cmp cut find head mktemp mv nproc od rm sed sha256sum shasum \
      sort stat sysctl tr xargs; do
      if p=$(command -v "$t"); then ln -s "$p" "$noperl/$t"; fi
    done
    export INTEGRITY_DB="$tmp/noperl.db"
    run 0 "$cli" init "$plain"
    run 0 env PATH="$noperl" "$cli" check "$plain"
    assert "warning: perl not found, skipping UTF-8 validation"
    assert "p.log: Unmodified"

    # The entries must come from the same bytes the signature is checked on. A shim awk
    # puts the genuine store back after the first awk read, which stands in for an
    # attacker who renames a forged store in for one read only. Reading the store twice
    # would accept the forged entries (exit 1, Untracked); one read sees the forgery.
    swap=$tmp/shim-swap
    mkdir "$swap"
    export INTEGRITY_DB="$tmp/swap.db" INTEGRITY_KEY="$tmp.key3"
    run 0 "$cli" init "$plain"
    cp "$INTEGRITY_DB" "$tmp/genuine.db"
    grep -vF "$plain/p.log" "$tmp/genuine.db" >"$INTEGRITY_DB" # entry gone, signature kept
    cat >"$swap/awk" <<EOF
#!/bin/sh
"$(command -v awk)" "\$@"
rc=\$?
[ -e "$tmp/swapped" ] || { : >"$tmp/swapped"; cp "$tmp/genuine.db" "$INTEGRITY_DB"; }
exit \$rc
EOF
    chmod +x "$swap/awk"
    run 2 env PATH="$swap:$PATH" "$cli" check "$plain"
    assert "signature mismatch"
    unset INTEGRITY_KEY

    # a failed rename of the temp store is an environment error (2) and leaves no temp file
    nomv=$tmp/shim-mv
    mkdir "$nomv"
    printf '#!/bin/sh\nexit 1\n' >"$nomv/mv"
    chmod +x "$nomv/mv"
    run 2 env PATH="$nomv:$PATH" INTEGRITY_DB="$tmp/mv.db" "$cli" init "$plain"
    [ -z "$(find "$tmp" -maxdepth 1 -name 'mv.db*')" ] || fail "failed rename left a store or temp file"
  fi

  rm -rf "$tmp" "$tmp".* # keys and their .last records sit beside $tmp
  echo "ok: $impl"
done

# A file replaced between the walk and the hash: a save-by-rename is hashed, a symlink is
# refused. The race cannot be timed, so this calls python's sha256() with the walk's old stat.
tmp=$(mktemp -d "$TMPDIR/integrity.XXXXXX")
impl=python/integrity-check
python3 - "$PWD/$impl" "$tmp" <<'EOF' || fail "replaced-file handling"
import hashlib, importlib.machinery, importlib.util, os, signal, sys
loader = importlib.machinery.SourceFileLoader("ic", sys.argv[1])
ic = importlib.util.module_from_spec(importlib.util.spec_from_loader("ic", loader))
loader.exec_module(ic)
p = os.path.join(sys.argv[2], "f")
with open(p, "w") as f:
    f.write("old")
st = os.lstat(p)
with open(p + ".new", "w") as f:
    f.write("new")
os.replace(p + ".new", p)
assert ic.sha256(p, st) == hashlib.sha256(b"new").hexdigest(), "save-by-rename not hashed"
assert ic.under("/etc/hosts", "/") and ic.under("/a/b", "/a/") and not ic.under("/ab", "/a"), "under"
# the target exists before p is removed, so it cannot reuse p's inode number
st = os.lstat(p)
with open(os.path.join(sys.argv[2], "t"), "w") as f:
    f.write("t")
os.remove(p)
os.symlink("t", p)
try:
    ic.sha256(p, st)
except SystemExit as e:
    assert e.code == 2, e.code
else:
    raise AssertionError("symlink swap was hashed")
# a FIFO swapped in is refused at once; the alarm kills a run that waits for a writer
os.remove(p)
with open(p, "w") as f:
    f.write("x")
st = os.lstat(p)
os.mkfifo(p + ".fifo")
os.replace(p + ".fifo", p)
signal.alarm(5)
try:
    ic.sha256(p, st)
except SystemExit as e:
    assert e.code == 2, e.code
else:
    raise AssertionError("fifo swap was hashed")
signal.alarm(0)
EOF
rm -rf "$tmp"
echo "ok: python replaced-file handling"

# All three must write the same store, signature included (line order may differ).
if [ ${#BUILT[@]} -lt 2 ]; then
  echo "skip: cross-implementation comparison needs 2+ built implementations"
else
  tmp=$(mktemp -d "$TMPDIR/integrity.XXXXXX")
  printf 'shared\n' >"$tmp/x.log"
  printf 'sp\n' >"$tmp/two  spaces.log"
  (umask 077 && head -c 32 /dev/urandom >"$tmp.key") # a hand-made key must be private too
  export INTEGRITY_KEY="$tmp.key"
  for impl in "${BUILT[@]}"; do
    INTEGRITY_DB="$tmp.db.${impl//\//_}" "$(path_of "$impl")" init "$tmp" >/dev/null
    cmp -s <(sort "$tmp.db.${BUILT[0]//\//_}") <(sort "$tmp.db.${impl//\//_}") ||
      fail "implementations disagree on the store (hash, metadata or signature)"
  done
  rm -rf "$tmp" "$tmp".*
  echo "ok: implementations agree, signatures included"
fi
