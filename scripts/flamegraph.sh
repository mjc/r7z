#!/usr/bin/env bash

# flamegraph.sh — convenience wrapper for benchmark profiling and comparison
#
# Usage:
#   ./scripts/flamegraph.sh bench         # pprof flamegraph via cargo bench
#   ./scripts/flamegraph.sh hyperfine     # wall-clock comparison via hyperfine

set -e

FIXTURE="target/bench-fixtures/1mb.7z"

bench_mode() {
    echo "Running cargo bench with pprof flamegraph profiler..."
    cargo bench --bench comparison -- --profile-time 10
    echo ""
    echo "Flamegraphs written to:"
    find target/criterion -name "flamegraph.svg" | sort
}

hyperfine_mode() {
    if [ ! -f "$FIXTURE" ]; then
        echo "Fixture not found. Run 'cargo bench --bench comparison' first to generate it."
        exit 1
    fi
    if ! command -v hyperfine &>/dev/null; then
        echo "hyperfine not found. Install with: cargo install hyperfine"
        exit 1
    fi

    echo "Comparing extract performance..."
    hyperfine --warmup 3 \
        "7z x -so $FIXTURE" \
        "7za x -so $FIXTURE"
}

case "${1:-bench}" in
    bench)      bench_mode ;;
    hyperfine)  hyperfine_mode ;;
    *)          echo "Usage: $0 [bench|hyperfine]"; exit 1 ;;
esac
