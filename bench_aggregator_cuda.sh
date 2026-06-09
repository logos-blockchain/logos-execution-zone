#!/usr/bin/env bash
# Benchmarks the aggregator circuit (core and strict variants) with CUDA acceleration.
#
# Fixtures must be generated first:
#   cargo run --release -p ppe_test_data_gen -- --output ppe_fixtures.bin
#
# Usage:
#   ./bench_aggregator_cuda.sh
#
# Environment:
#   PPE_FIXTURES  — path to fixture file (default: ppe_fixtures.bin)
#   COUNTS        — space-separated list of transaction counts (default: "1 3 5")

set -euo pipefail

# Point the build at CUDA 13.0 (required for Blackwell / compute_120).
export NVCC=/usr/local/cuda-13.0/bin/nvcc
export CUDA_HOME=/usr/local/cuda-13.0
export PATH="/usr/local/cuda-13.0/bin:$PATH"

FIXTURES="$(realpath "${PPE_FIXTURES:-ppe_fixtures.bin}")"
COUNTS="${COUNTS:-2 3 4 5 6 7 8 10 12 14 16}"
SEGMENT_LIMIT_PO2="${PPE_SEGMENT_LIMIT_PO2-19}"

if [ ! -f "$FIXTURES" ]; then
    echo "ERROR: fixture file '$FIXTURES' not found."
    echo "Generate it first:"
    echo "  cargo run --release -p ppe_test_data_gen -- --output $FIXTURES"
    exit 1
fi

printf "\n%-6s  %-8s  %14s  %20s\n" "n" "variant" "proving_ms" "proof_size_bytes"
printf "%-6s  %-8s  %14s  %20s\n" "------" "--------" "--------------" "--------------------"

run_bench() {
    local count=$1
    local strict=$2
    local variant
    variant=$([ "$strict" = "1" ] && echo "strict" || echo "core")

    local segment_limit_env=()
    if [ -n "$SEGMENT_LIMIT_PO2" ]; then
        segment_limit_env=(PPE_SEGMENT_LIMIT_PO2="$SEGMENT_LIMIT_PO2")
    fi

    local line
    line=$(
        env \
        PPE_FIXTURES="$FIXTURES" \
        AGGREGATOR_COUNT="$count" \
        AGGREGATOR_STRICT="$strict" \
        "${segment_limit_env[@]}" \
        cargo test -p lee --features cuda,prove bench_aggregator -- --nocapture 2>&1 \
        | grep "\[lee::analytics\] aggregator" || true
    )

    if [ -z "$line" ]; then
        printf "%-6s  %-8s  %14s  %20s\n" "$count" "$variant" "failed" "-"
        return
    fi

    local proving_ms proof_size
    proving_ms=$(echo "$line" | grep -o 'proving_ms=[0-9]*'      | cut -d= -f2)
    proof_size=$(echo "$line" | grep -o 'proof_size_bytes=[0-9]*' | cut -d= -f2)

    printf "%-6s  %-8s  %14s  %20s\n" "$count" "$variant" "$proving_ms" "$proof_size"
}

for count in $COUNTS; do
    run_bench "$count" "0"
    run_bench "$count" "1"
done

printf "\n"
