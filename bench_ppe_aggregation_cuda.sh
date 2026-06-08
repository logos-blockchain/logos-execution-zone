#!/usr/bin/env bash
# Runs the PPE aggregation test (CUDA-accelerated prover) across a range of fixture counts
# and prints a results table.
#
# Usage:
#   ./bench_ppe_aggregation_cuda.sh
#
# Environment:
#   PPE_FIXTURES          - path to the fixture file (default: ppe_fixtures.bin)
#   COUNTS                - space-separated list of counts to test (default: powers of 2, 1..256)
#   PPE_SEGMENT_LIMIT_PO2 - log2 of the max cycles per segment (default: 19). Lower values
#                           reduce peak GPU memory at the cost of more segments / proving time —
#                           needed on memory-constrained GPUs (risc0's default of 20 OOMs on an
#                           8 GB card past n=1). Set to empty to use risc0's default.
#
# Example:
#   PPE_FIXTURES=/path/to/ppe_fixtures.bin COUNTS="4 8 16" ./bench_ppe_aggregation_cuda.sh

set -euo pipefail

# This machine's distro CUDA toolkit (12.0) doesn't recognise the RTX 5050's
# Blackwell architecture (compute_120); point the build at the NVIDIA-provided
# CUDA 13.0 toolkit installed under /usr/local instead.
export NVCC=/usr/local/cuda-13.0/bin/nvcc
export CUDA_HOME=/usr/local/cuda-13.0
export PATH="/usr/local/cuda-13.0/bin:$PATH"

FIXTURES="$(realpath "${PPE_FIXTURES:-ppe_fixtures.bin}")"
COUNTS="${COUNTS:-1 2 4 6 8 10 12 14 16}"
SEGMENT_LIMIT_PO2="${PPE_SEGMENT_LIMIT_PO2-19}"

if [ ! -f "$FIXTURES" ]; then
    echo "ERROR: fixture file '$FIXTURES' not found."
    echo "Generate it first:"
    echo "  RISC0_DEV_MODE=1 cargo run --release -p ppe_test_data_gen -- --output $FIXTURES"
    exit 1
fi

printf "\n%-6s  %14s  %20s\n" "n" "proving_ms" "proof_size_bytes"
printf "%-6s  %14s  %20s\n" "------" "--------------" "--------------------"

for count in $COUNTS; do
    # Only forward PPE_SEGMENT_LIMIT_PO2 when set — the guest panics if it
    # receives an empty value, whereas an absent var falls back to risc0's default.
    segment_limit_env=()
    if [ -n "$SEGMENT_LIMIT_PO2" ]; then
        segment_limit_env=(PPE_SEGMENT_LIMIT_PO2="$SEGMENT_LIMIT_PO2")
    fi

    line=$(
        env \
        PPE_FIXTURES="$FIXTURES" \
        PPE_FIXTURES_COUNT="$count" \
        "${segment_limit_env[@]}" \
        cargo test -p lee --features cuda aggregate_ppe_proofs_from_fixtures -- --nocapture 2>&1 \
        | grep -v "^test_programs:" \
        | grep "\[lee::analytics\] ppe_aggregation" || true
    )

    if [ -z "$line" ]; then
        printf "%-6s  %14s  %20s\n" "$count" "skipped" "-"
        continue
    fi

    n=$(echo "$line"          | grep -o 'n=[0-9]*'               | cut -d= -f2)
    proving_ms=$(echo "$line" | grep -o 'proving_ms=[0-9]*'      | cut -d= -f2)
    proof_size=$(echo "$line" | grep -o 'proof_size_bytes=[0-9]*'| cut -d= -f2)

    printf "%-6s  %14s  %20s\n" "$n" "$proving_ms" "$proof_size"
done

printf "\n"
