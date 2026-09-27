#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R7Z_BIN="${R7Z_BIN:-$ROOT/target/release/r7z}"
P7Z_BIN="${P7ZIP_BIN:-$("$ROOT/scripts/ensure_p7zip_oracle.sh")}"
SIZES="${SIZES:-1K,4K,16K,64K,256K,1M,4M,16M,64M,256M,1G}"
RUNS="${RUNS:-5}"
MX="${MX:-5}"
R7Z_THREADS="${R7Z_THREADS:-auto}"
P7ZIP_THREADS="${P7ZIP_THREADS:-auto}"
PATTERN="${PATTERN:-zero}"
WORKDIR="${WORKDIR:-$(mktemp -d)}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
FLAMEGRAPHS="${FLAMEGRAPHS:-0}"
FLAMEGRAPH_OPS="${FLAMEGRAPH_OPS:-l,t,a}"
FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-$ROOT/target/flamegraphs/p7zip-compare}"
FLAMEGRAPH_ROOT="${FLAMEGRAPH_ROOT:-0}"

usage() {
  cat <<'EOF'
Usage: scripts/compare_p7zip_perf.sh [options]

Benchmarks `r7z` against the pinned p7zip oracle for:
  - `l`  : listing/header parse
  - `t`  : read/decode/CRC validation without writing files
  - `a`  : archive creation

Default size matrix spans 1 KiB through 1 GiB on a log scale:
  1K,4K,16K,64K,256K,1M,4M,16M,64M,256M,1G

Options:
  --sizes CSV       Comma-separated sizes accepted by `truncate` (default: built-in matrix)
  --runs N          Number of timing runs per command (default: 5)
  --mx N            Compression level passed to both tools (default: 5)
  --r7z-threads N    r7z thread count (default: auto)
  --p7zip-threads N  Oracle thread count (default: auto)
  --pattern MODE    `zero` (default), `random`, or `sparse-zero`
  --workdir DIR     Reuse a specific working directory
  --keep-workdir    Preserve generated payloads/archives
  --flamegraphs     Generate r7z flamegraphs alongside timings
  --flamegraph-ops CSV
                    Which r7z ops to flamegraph: `l,t,a` (default: all)
  --flamegraph-dir DIR
                    Output directory for flamegraph SVGs
  --root-flamegraphs
                    Pass `--root` to `cargo flamegraph`
  --help            Show this text

Notes:
  - `zero` materializes full files, including 1G, for honest file-I/O benchmarking.
  - `sparse-zero` is the fast shortcut when you only care about logical size.
  - `random` materializes the full input bytes and can be expensive above ~hundreds of MiB.
  - This script assumes `target/release/r7z` already exists; run `cargo build --release --bin r7z` first.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sizes)
      SIZES="$2"
      shift 2
      ;;
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --mx)
      MX="$2"
      shift 2
      ;;
    --p7zip-threads)
      P7ZIP_THREADS="$2"
      shift 2
      ;;
    --r7z-threads)
      R7Z_THREADS="$2"
      shift 2
      ;;
    --pattern)
      PATTERN="$2"
      shift 2
      ;;
    --workdir)
      WORKDIR="$2"
      shift 2
      ;;
    --keep-workdir)
      KEEP_WORKDIR=1
      shift
      ;;
    --flamegraphs)
      FLAMEGRAPHS=1
      shift
      ;;
    --flamegraph-ops)
      FLAMEGRAPH_OPS="$2"
      shift 2
      ;;
    --flamegraph-dir)
      FLAMEGRAPH_DIR="$2"
      shift 2
      ;;
    --root-flamegraphs)
      FLAMEGRAPH_ROOT=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -x "$R7Z_BIN" ]]; then
  echo "r7z binary not found at $R7Z_BIN; run: cargo build --release --bin r7z" >&2
  exit 1
fi

if [[ "$PATTERN" != "zero" && "$PATTERN" != "random" && "$PATTERN" != "sparse-zero" ]]; then
  echo "unsupported pattern: $PATTERN" >&2
  exit 2
fi

if [[ "$P7ZIP_THREADS" != "auto" && ! "$P7ZIP_THREADS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--p7zip-threads expects a positive integer or auto" >&2
  exit 2
fi
if [[ "$R7Z_THREADS" != "auto" && ! "$R7Z_THREADS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--r7z-threads expects a positive integer or auto" >&2
  exit 2
fi

p7zip_thread_args=()
if [[ "$P7ZIP_THREADS" != "auto" ]]; then
  p7zip_thread_args=("-mmt=$P7ZIP_THREADS")
fi
r7z_thread_args=()
if [[ "$R7Z_THREADS" != "auto" ]]; then
  r7z_thread_args=("-mmt=$R7Z_THREADS")
fi

if [[ "$KEEP_WORKDIR" != "1" ]]; then
  trap 'rm -rf "$WORKDIR"' EXIT
fi

mkdir -p "$WORKDIR"

if [[ "$FLAMEGRAPHS" == "1" ]]; then
  if ! cargo flamegraph --help >/dev/null 2>&1; then
    echo "cargo flamegraph is required; install it with: cargo install flamegraph" >&2
    exit 1
  fi
  if ! command -v perf >/dev/null 2>&1; then
    echo "perf is required for flamegraphs and was not found in PATH." >&2
    echo "Try: devenv shell -- bash scripts/compare_p7zip_perf.sh ..." >&2
    exit 1
  fi
  mkdir -p "$FLAMEGRAPH_DIR"
fi

shell_quote() {
  printf '%q' "$1"
}

average_seconds() {
  awk '{sum += $1; count += 1} END {if (count == 0) exit 1; printf "%.6f", sum / count}'
}

ratio_string() {
  awk -v a="$1" -v b="$2" 'BEGIN {printf "%.2fx", a / b}'
}

median_and_range() {
  sort -n | awk '{samples[NR] = $1} END {
    if (NR == 0) exit 1
    middle = int(NR / 2) + 1
    median = NR % 2 ? samples[middle] : (samples[middle - 1] + samples[middle]) / 2
    printf "%.3f %.3f %.3f\n", median, samples[1], samples[NR]
  }'
}

time_direct() {
  TIMEFORMAT='%3R'
  { time "$@" >/dev/null; } 2>&1
}

op_selected() {
  local op="$1"
  local item
  IFS=',' read -r -a ops <<<"$FLAMEGRAPH_OPS"
  for item in "${ops[@]}"; do
    if [[ "$item" == "$op" ]]; then
      return 0
    fi
  done
  return 1
}

time_command() {
  local prep="$1"
  local cmd="$2"
  local samples

  samples="$(
    for _ in $(seq 1 "$RUNS"); do
      bash -lc "$prep" >/dev/null 2>&1
      TIMEFORMAT='%3R'
      { time bash -lc "$cmd" >/dev/null; } 2>&1
    done
  )"
  printf '%s\n' "$samples" | average_seconds
}

materialize_payload() {
  local size="$1"
  local path="$2"
  local bytes
  rm -f "$path"
  bytes="$(numfmt --from=iec "$size")"
  case "$PATTERN" in
    zero)
      head -c "$bytes" /dev/zero > "$path"
      ;;
    random)
      head -c "$bytes" /dev/urandom > "$path"
      ;;
    sparse-zero)
      truncate -s "$size" "$path"
      ;;
  esac
}

generate_flamegraph() {
  local label="$1"
  shift
  local out="$FLAMEGRAPH_DIR/$label.svg"
  local cargo_args=(flamegraph --profile profiling --bin r7z -o "$out")
  if [[ "$FLAMEGRAPH_ROOT" == "1" ]]; then
    cargo_args+=(--root)
  fi
  cargo_args+=(-- "$@")
  rm -f "$ROOT/perf.data" "$ROOT/perf.data.old"
  (
    cd "$ROOT"
    cargo "${cargo_args[@]}" >/dev/null
  )
  if [[ -f "$ROOT/perf.data" ]]; then
    mv "$ROOT/perf.data" "$FLAMEGRAPH_DIR/$label.perf.data"
  fi
  rm -f "$ROOT/perf.data.old"
}

echo "# r7z vs p7zip CLI performance"
echo
echo "- r7z: $R7Z_BIN"
echo "- p7zip: $P7Z_BIN"
echo "- sizes: $SIZES"
echo "- runs per command: $RUNS"
echo "- compression level: -mx=$MX"
echo "- r7z threads: $R7Z_THREADS"
echo "- p7zip threads: $P7ZIP_THREADS"
echo "- payload pattern: $PATTERN"
echo "- workdir: $WORKDIR"
if [[ "$FLAMEGRAPHS" == "1" ]]; then
  echo "- flamegraphs: $FLAMEGRAPH_OPS -> $FLAMEGRAPH_DIR"
fi
echo
echo "| Size | Operation | r7z (s) | p7zip (s) | r7z/p7zip |"
echo "| --- | --- | ---: | ---: | ---: |"

IFS=',' read -r -a size_list <<<"$SIZES"
for size in "${size_list[@]}"; do
  payload="$WORKDIR/payload-$size.bin"
  source_archive="$WORKDIR/source-$size.7z"
  r7z_archive="$WORKDIR/r7z-$size.7z"
  p7zip_archive="$WORKDIR/p7zip-$size.7z"

  materialize_payload "$size" "$payload"
  "$P7Z_BIN" a -bd -bb0 "${p7zip_thread_args[@]}" "-mx=$MX" "$source_archive" "$payload" >/dev/null

  payload_q="$(shell_quote "$payload")"
  source_archive_q="$(shell_quote "$source_archive")"
  r7z_archive_q="$(shell_quote "$r7z_archive")"
  p7zip_archive_q="$(shell_quote "$p7zip_archive")"
  r7z_q="$(shell_quote "$R7Z_BIN")"
  p7z_q="$(shell_quote "$P7Z_BIN")"

  r7z_list="$(time_command "true" "$r7z_q l $source_archive_q >/dev/null")"
  p7zip_list="$(time_command "true" "$p7z_q l $source_archive_q >/dev/null")"
  printf '| %s | l | %s | %s | %s |\n' \
    "$size" "$r7z_list" "$p7zip_list" "$(ratio_string "$r7z_list" "$p7zip_list")"
  if [[ "$FLAMEGRAPHS" == "1" ]] && op_selected "l"; then
    generate_flamegraph "list-$size" l "$source_archive"
  fi

  r7z_test="$(time_command "true" "$r7z_q t $source_archive_q >/dev/null")"
  p7zip_test="$(time_command "true" "$p7z_q t $source_archive_q >/dev/null")"
  printf '| %s | t | %s | %s | %s |\n' \
    "$size" "$r7z_test" "$p7zip_test" "$(ratio_string "$r7z_test" "$p7zip_test")"
  if [[ "$FLAMEGRAPHS" == "1" ]] && op_selected "t"; then
    generate_flamegraph "test-$size" t "$source_archive"
  fi

  r7z_samples=()
  p7zip_samples=()
  for ((run = 1; run <= RUNS; run++)); do
    if ((run % 2 == 1)); then
      rm -f "$r7z_archive"
      r7z_samples+=("$(time_direct "$R7Z_BIN" a "-mx=$MX" "${r7z_thread_args[@]}" "$r7z_archive" "$payload")")
      rm -f "$p7zip_archive"
      p7zip_samples+=("$(time_direct "$P7Z_BIN" a -bd -bb0 "${p7zip_thread_args[@]}" "-mx=$MX" "$p7zip_archive" "$payload")")
    else
      rm -f "$p7zip_archive"
      p7zip_samples+=("$(time_direct "$P7Z_BIN" a -bd -bb0 "${p7zip_thread_args[@]}" "-mx=$MX" "$p7zip_archive" "$payload")")
      rm -f "$r7z_archive"
      r7z_samples+=("$(time_direct "$R7Z_BIN" a "-mx=$MX" "${r7z_thread_args[@]}" "$r7z_archive" "$payload")")
    fi
  done
  read -r r7z_create r7z_min r7z_max <<<"$(printf '%s\n' "${r7z_samples[@]}" | median_and_range)"
  read -r p7zip_create p7zip_min p7zip_max <<<"$(printf '%s\n' "${p7zip_samples[@]}" | median_and_range)"
  printf '| %s | a | %s [%s,%s] | %s [%s,%s] | %s |\n' \
    "$size" "$r7z_create" "$r7z_min" "$r7z_max" "$p7zip_create" "$p7zip_min" "$p7zip_max" "$(ratio_string "$r7z_create" "$p7zip_create")"
  if [[ "$FLAMEGRAPHS" == "1" ]] && op_selected "a"; then
    rm -f "$WORKDIR/flamegraph-$size.7z"
    generate_flamegraph "add-$size" a "-mx=$MX" "${r7z_thread_args[@]}" "$WORKDIR/flamegraph-$size.7z" "$payload"
  fi
done
