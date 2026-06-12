#!/usr/bin/env bash
# Benchmarks the sequencer aggregator host/guest pair (sequencer_aggregator.rs) with CUDA
# acceleration.
#
# Test transactions are loaded from a cache (target/sequencer_aggregator_bench_transactions.bin,
# BENCH_MAX_TRANSACTIONS=8 by default); `AGGREGATOR_COUNT` truncates that cached set, so this
# script does NOT regenerate transactions. If the cache doesn't exist yet, generate it first
# (one-time cost, produces real, non-dev-mode PPE proofs):
#
#   NVCC=/usr/local/cuda-13.0/bin/nvcc \
#   CUDA_HOME=/usr/local/cuda-13.0 \
#   PATH="/usr/local/cuda-13.0/bin:$PATH" \
#   PPE_SEGMENT_LIMIT_PO2=19 \
#   cargo test -p lee --features cuda,prove --lib \
#     sequencer_aggregator::tests::bench_sequencer_aggregator -- --nocapture
#
# Usage:
#   ./bench_sequencer_aggregator_cuda.sh
#
# Environment:
#   COUNTS             — space-separated list of transaction counts (default: "2 4 8"); each
#                         must be <= BENCH_MAX_TRANSACTIONS in sequencer_aggregator.rs
#   PPE_SEGMENT_LIMIT_PO2 — segment size limit (log2 cycles/segment) passed to the executor
#                         (default: 19)

set -euo pipefail

# Point the build at CUDA 13.0 (required for Blackwell / compute_120).
export NVCC=/usr/local/cuda-13.0/bin/nvcc
export CUDA_HOME=/usr/local/cuda-13.0
export PATH="/usr/local/cuda-13.0/bin:$PATH"

COUNTS="${COUNTS:-2 4 8}"
export PPE_SEGMENT_LIMIT_PO2="${PPE_SEGMENT_LIMIT_PO2-19}"

printf "\n%-6s  %14s  %20s\n" "n" "proving_ms" "proof_size_bytes"
printf "%-6s  %14s  %20s\n" "------" "--------------" "--------------------"

run_bench() {
    local count=$1

    local line
    line=$(
        AGGREGATOR_COUNT="$count" \
        cargo test -p lee --features cuda,prove --lib \
            sequencer_aggregator::tests::bench_sequencer_aggregator -- --nocapture 2>&1 \
        | grep "\[lee::analytics\] sequencer_aggregator" || true
    )

    if [ -z "$line" ]; then
        printf "%-6s  %14s  %20s\n" "$count" "failed" "-"
        return
    fi

    local proving_ms proof_size
    proving_ms=$(echo "$line" | grep -o 'proving_ms=[0-9]*' | cut -d= -f2)
    proof_size=$(echo "$line" | grep -o 'proof_size_bytes=[0-9]*' | cut -d= -f2)

    printf "%-6s  %14s  %20s\n" "$count" "$proving_ms" "$proof_size"
}

for count in $COUNTS; do
    run_bench "$count"
done

printf "\n"
