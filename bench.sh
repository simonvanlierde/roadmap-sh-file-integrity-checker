#!/usr/bin/env bash
# Benchmarks the three implementations with hyperfine, writes BENCHMARKS.md.
set -euo pipefail
cd "$(dirname "$0")"

FILES=${FILES:-500}           # small files in the "many files" tree
SIZE_KB=${SIZE_KB:-4}         # size of each small file
BIG_MB=${BIG_MB:-256}         # size of the single large file
DIRTY_PCT=${DIRTY_PCT:-10}    # share of the tree modified before the incremental check
STORE_PAD=${STORE_PAD:-50000} # synthetic entries padding the "large store" baseline

work=$(mktemp -d "${TMPDIR:-/tmp}/integrity-bench.XXXXXX")
trap 'rm -rf "$work"' EXIT
many=$work/many
big=$work/big
dirty=$work/dirty
small=$work/small
mkdir "$many" "$big" "$dirty" "$small"

echo "generating fixtures: $FILES x ${SIZE_KB}KB, 1 x ${BIG_MB}MB ..."
# one read split into $FILES pieces; a dd per file is ~15x slower
dd if=/dev/urandom bs=1024 count=$((FILES * SIZE_KB)) 2>/dev/null |
  split -b "$((SIZE_KB * 1024))" -a 4 - "$many/log-"
dd if=/dev/urandom of="$big/huge.log" bs=1048576 count="$BIG_MB" 2>/dev/null
cp "$many"/* "$dirty"/
dd if=/dev/urandom bs=1024 count=$((10 * SIZE_KB)) 2>/dev/null |
  split -b "$((SIZE_KB * 1024))" -a 2 - "$small/f-"

names=() cmds=()
for i in bash python rust; do
  case $i in
  rust) c=$PWD/rust/target/release/integrity-check ;;
  *) c=$PWD/$i/integrity-check ;;
  esac
  if [ -x "$c" ]; then
    names+=("$i") cmds+=("$c")
  else
    echo "skip: $i not built"
  fi
done
[ "${#names[@]}" -gt 0 ] || {
  echo "error: no implementations built" >&2
  exit 2
}

# One store per scenario, shared by all three (they write byte-identical files) and
# seeded by a single un-benchmarked init.
shared=$work/shared.db
dirtydb=$work/dirty.db
bigstore=$work/bigstore.db

echo "seeding baselines ..."
INTEGRITY_DB=$shared "${cmds[0]}" init "$many" >/dev/null
INTEGRITY_DB=$shared "${cmds[0]}" init "$big" >/dev/null
INTEGRITY_DB=$dirtydb "${cmds[0]}" init "$dirty" >/dev/null
# modify a slice of the tree so --fast re-hashes this share and reuses the rest
n=0
for f in "$dirty"/*; do
  n=$((n + 1))
  [ $((n % (100 / DIRTY_PCT))) -eq 0 ] && printf 'x' >>"$f"
done

INTEGRITY_DB=$bigstore "${cmds[0]}" init "$small" >/dev/null
# pad with entries under a root nobody checks: varies store size independently of tree size
{
  head -1 "$bigstore"
  {
    tail -n +2 "$bigstore"
    awk -v n="$STORE_PAD" 'BEGIN {
      for (i = 0; i < n; i++)
        printf "%064x\t1024\t1700000000\t/synthetic/root%04d/file%06d.log\n", i, i / 100, i
    }'
  } | LC_ALL=C sort -t"$(printf '\t')" -k4
} >"$bigstore.pad" && mv "$bigstore.pad" "$bigstore"

# <export-file> <action> <target>
bench() {
  local out=$1 action=$2 target=$3 args=() k
  for k in "${!names[@]}"; do
    # -N: below ~5ms hyperfine cannot calibrate shell startup and floors at 0.0ms.
    # Quote the paths, not $action: hyperfine still word-splits the string.
    args+=(-n "${names[k]}" "'${cmds[k]}' $action '$target'")
  done
  # 25 runs: fewer put sigma at up to half the mean on a laptop. -i because `check`
  # exits 1 on any difference; smoke() below rules out the broken exit codes.
  hyperfine -i -N --warmup "${WARMUP:-5}" --runs "${RUNS:-25}" --export-markdown "$out" "${args[@]}"
}

# <action> <target>: insist on exit <= 1, so -i above cannot hide an erroring command
smoke() {
  local action=$1 target=$2 k rc
  for k in "${!names[@]}"; do
    rc=0
    # shellcheck disable=SC2086  # $action carries the --fast flag and must split
    "${cmds[k]}" $action "$target" >/dev/null 2>&1 || rc=$?
    [ "$rc" -le 1 ] || {
      echo "error: ${names[k]} exited $rc on '$action $target'" >&2
      exit 2
    }
  done
}

# <slug>|<action>|<target>|<db>|<heading>, driving both the runs and the report below.
# `check` on a clean tree lands within noise of `init`, so those rows are not duplicated.
workloads=(
  # per-file cost at scale, plus the store write path: walk, hash everything, sort, write
  "init-many|init|$many|$shared|init: $FILES files x ${SIZE_KB} KB"
  # the steady state --fast exists for: stat everything, re-hash the changed slice, reuse the rest
  "check-many-dirty|check --fast|$dirty|$dirtydb|check --fast: $FILES files x ${SIZE_KB} KB (${DIRTY_PCT}% modified, the rest reused)"
  # single-stream hash throughput, one core, no per-file overhead to hide behind
  "init-big|init|$big|$shared|init: 1 file x ${BIG_MB} MB"
  # the floor: one unchanged file, so whatever this costs is startup plus store handling
  "check-big-fast|check --fast|$big|$shared|check --fast: 1 file x ${BIG_MB} MB (metadata unchanged, nothing re-hashed)"
  # the same floor with a large baseline: the delta against the row above is store size alone
  "check-bigstore|check --fast|$small|$bigstore|check --fast: 10-file target inside a $((STORE_PAD + 10))-entry store"
)
for w in "${workloads[@]}"; do
  IFS='|' read -r slug action target db heading <<<"$w"
  echo
  echo "=== $heading ==="
  export INTEGRITY_DB=$db
  smoke "$action" "$target"
  bench "$work/$slug.md" "$action" "$target"
done

{
  echo "# Benchmarks"
  echo
  echo "Generated by \`./bench.sh\` with [hyperfine](https://github.com/sharkdp/hyperfine)."
  echo
  echo '```sh'
  cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null ||
    sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1)
  echo "machine: ${cpu:-$(uname -m)}, $(uname -sr)"
  # nproc counts only the CPUs this run may use, so a pinned run shows it
  echo "cpus:    $(nproc 2>/dev/null || sysctl -n hw.ncpu)"
  echo "bash:    $(bash --version | head -1)"
  echo "python:  $(python3 -V)"
  echo "rustc:   $(rustc --version 2>/dev/null || echo 'n/a')"
  echo "runs:    ${RUNS:-25} per command, ${WARMUP:-5} warmup"
  echo '```'
  echo
  for w in "${workloads[@]}"; do
    IFS='|' read -r slug _ _ _ heading <<<"$w"
    echo "## $heading"
    echo
    cat "$work/$slug.md"
    echo
  done
} >BENCHMARKS.md

echo "wrote BENCHMARKS.md"
