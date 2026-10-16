#!/usr/bin/env bash
# Differential test: random trees, one random edit, and init/check/update on all three
# implementations. Fails on the first difference in exit code or stdout, naming the seed.
set -euo pipefail
cd "$(dirname "$0")"

IMPLS=(bash/integrity-check python/integrity-check rust/target/release/integrity-check)
for impl in "${IMPLS[@]}"; do
  [ -x "$impl" ] || {
    echo "FAIL: $impl not built" >&2
    exit 1
  }
done

# Spaces, unicode and leading dashes; tab and newline are refused by design (see test.sh).
NAMES=(plain 'with space' 'two  spaces' 'trail ' ünïcode 日本語 -dash --double '-x y' café.log)

pick() { echo "${NAMES[RANDOM % ${#NAMES[@]}]}"; }

build() { # <dir> <depth>: a few files, maybe empty, and maybe a few subdirs
  local dir=$1 depth=$2 i n
  mkdir -p "$dir"
  n=$((RANDOM % 4 + 1))
  for ((i = 0; i < n; i++)); do
    if ((RANDOM % 3)); then printf '%s\n' "$RANDOM" >"$dir/$(pick)"; else : >"$dir/$(pick)"; fi
  done
  ((depth < 3)) || return 0
  n=$((RANDOM % 3))
  for ((i = 0; i < n; i++)); do build "$dir/$(pick).d" $((depth + 1)); done
}

# Runs <cmd> on every implementation, each with its own store kept across steps.
compare() { # <cmd> <target>
  local impl db ref_code ref_out code out
  for impl in "${IMPLS[@]}"; do
    db=$tmp/db.${impl%%/*}
    out=$(INTEGRITY_DB="$db" "$PWD/$impl" "$1" "$2" 2>/dev/null) && code=0 || code=$?
    out=${out//"$db"/<db>}
    if [ "$impl" = "${IMPLS[0]}" ]; then
      ref_code=$code ref_out=$out
    elif [ "$code" != "$ref_code" ] || [ "$out" != "$ref_out" ]; then
      echo "FAIL seed $seed: '$1' differs between ${IMPLS[0]} and $impl" >&2
      echo "--- ${IMPLS[0]} (exit $ref_code)" >&2
      printf '%s\n' "$ref_out" >&2
      echo "--- $impl (exit $code)" >&2
      printf '%s\n' "$out" >&2
      exit 1
    fi
  done
}

TMPDIR=${TMPDIR:-/tmp}
for seed in $(seq 1 50); do
  RANDOM=$seed
  tmp=$(mktemp -d "${TMPDIR%/}/difftest.XXXXXX")
  build "$tmp/tree" 0
  compare init "$tmp/tree"

  files=() # no mapfile: macOS ships bash 3.2
  while IFS= read -r -d '' p; do files+=("$p"); done < <(find "$tmp/tree" -type f -print0)
  f=${files[RANDOM % ${#files[@]}]}
  case $((RANDOM % 3)) in
  0) printf 'edit %s\n' "$RANDOM" >>"$f" ;;
  1) rm -- "$f" ;;
  2) printf 'new\n' >"$(dirname -- "$f")/$(pick).new" ;;
  esac

  compare check "$tmp/tree"
  compare update "$tmp/tree"
  rm -rf "$tmp"
done
echo "ok: 50 seeds, all three implementations agree"
