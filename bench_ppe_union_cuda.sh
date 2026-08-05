#!/usr/bin/env bash
# Runs the union-tree PPE aggregation benchmark (CUDA-accelerated recursion prover)
# across a range of fixture counts and prints a results table. GPU counterpart of
# bench_ppe_union.sh; compare against bench_ppe_aggregation_cuda.sh (guest-based).
#
# Usage:
#   ./bench_ppe_union_cuda.sh
#
# Environment:
#   PPE_FIXTURES - path to the fixture file (default: ppe_fixtures.bin)
#   COUNTS       - space-separated list of counts to test (default: 1..16)
#   UNION_MODES  - space-separated list of parallelism degrees (default: "1").
#                  Concurrent union proofs contend for VRAM on a single GPU — raise
#                  only after checking headroom (each recursion proof needs a few GB).
#
# Notes:
#   - PPE_SEGMENT_LIMIT_PO2 does not apply: union runs the recursion circuit only
#     (fixed size, no guest execution, no segments), and fits in 8 GB VRAM.
#
# Example:
#   PPE_FIXTURES=/path/to/ppe_fixtures.bin COUNTS="4 8 16" ./bench_ppe_union_cuda.sh

set -euo pipefail

# Same dev-mode semantics as risc0's is_dev_mode(): only 1/true/yes (case-insensitive)
# enable it.
case "$(echo "${RISC0_DEV_MODE:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes)
        echo "ERROR: refusing to benchmark with RISC0_DEV_MODE enabled — numbers would be meaningless."
        exit 1
        ;;
esac

# Prefer the NVIDIA-provided CUDA 13.0 toolkit under /usr/local when present
# (needed where the distro toolkit is too old for the GPU architecture); fall back
# to whatever nvcc is on PATH otherwise.
if [ -d /usr/local/cuda-13.0 ]; then
    export NVCC=/usr/local/cuda-13.0/bin/nvcc
    export CUDA_HOME=/usr/local/cuda-13.0
    export PATH="/usr/local/cuda-13.0/bin:$PATH"
fi

FIXTURES="$(realpath "${PPE_FIXTURES:-ppe_fixtures.bin}")"
COUNTS="${COUNTS:-1 2 4 6 8 10 12 14 16}"
MODES="${UNION_MODES:-1}"

if [ ! -f "$FIXTURES" ]; then
    echo "ERROR: fixture file '$FIXTURES' not found."
    echo "Generate it first (real proofs — do NOT use RISC0_DEV_MODE):"
    echo "  cargo run --release -p ppe_test_data_gen -- --output $FIXTURES"
    exit 1
fi

printf "\n%-6s %-6s %12s %10s %8s %18s %22s\n" \
    "n" "mode" "proving_ms" "verify_ms" "unions" "proof_size_bytes" "total_material_bytes"
printf "%-6s %-6s %12s %10s %8s %18s %22s\n" \
    "------" "------" "------------" "----------" "--------" "------------------" "----------------------"

for count in $COUNTS; do
    for mode in $MODES; do
        # NOTE: `cuda` alone enables risc0's prover but NOT lee's own `prove` feature,
        # which gates the union module — both are required.
        output=$(
            PPE_FIXTURES="$FIXTURES" \
            PPE_FIXTURES_COUNT="$count" \
            UNION_PARALLEL="$mode" \
            cargo test -p lee --release --features cuda,prove \
                bench_union_ppe_proofs_from_fixtures -- --nocapture 2>&1
        ) || {
            echo "ERROR: cargo test failed for n=$count mode=$mode:"
            echo "$output" | tail -20
            exit 1
        }
        line=$(echo "$output" | grep -v "^test_programs:" \
            | grep "\[lee::analytics\] ppe_union" || true)

        if [ -z "$line" ]; then
            printf "%-6s %-6s %12s %10s %8s %18s %22s\n" "$count" "$mode" "skipped" "-" "-" "-" "-"
            continue
        fi

        n=$(echo "$line"          | grep -o 'n=[0-9]*'                     | cut -d= -f2)
        mode_out=$(echo "$line"   | grep -o 'mode=[a-z0-9]*'               | cut -d= -f2)
        proving_ms=$(echo "$line" | grep -o 'proving_ms=[0-9]*'            | cut -d= -f2)
        verify_ms=$(echo "$line"  | grep -o 'verify_ms=[0-9]*'             | cut -d= -f2)
        unions=$(echo "$line"     | grep -o 'unions=[0-9]*'                | cut -d= -f2)
        proof_size=$(echo "$line" | grep -o 'proof_size_bytes=[0-9]*'      | cut -d= -f2)
        total=$(echo "$line"      | grep -o 'total_material_bytes=[0-9]*'  | cut -d= -f2)

        printf "%-6s %-6s %12s %10s %8s %18s %22s\n" \
            "$n" "$mode_out" "$proving_ms" "$verify_ms" "$unions" "$proof_size" "$total"
    done
done

printf "\n"
