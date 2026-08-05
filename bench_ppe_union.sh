#!/usr/bin/env bash
# Runs the union-tree PPE aggregation benchmark across a range of fixture counts and
# prints a results table. CPU counterpart of bench_ppe_union_cuda.sh; compare against
# bench_ppe_aggregation.sh (the guest-based approach).
#
# Usage:
#   ./bench_ppe_union.sh
#
# Environment:
#   PPE_FIXTURES - path to the fixture file (default: ppe_fixtures.bin)
#   COUNTS       - space-separated list of counts to test (default: 1..16)
#   UNION_MODES  - space-separated list of parallelism degrees (default: "1 4";
#                  1 = sequential, k>1 = up to k concurrent union proofs)
#
# Notes:
#   - Union proving is in-process (feature `prove`), so the test binary is built with
#     --release; there is no external r0vm doing the heavy lifting as in the guest
#     benchmark's default setup.
#   - PPE_SEGMENT_LIMIT_PO2 does not apply: recursion proofs are fixed size.
#
# Example:
#   PPE_FIXTURES=/path/to/ppe_fixtures.bin COUNTS="4 8 16" ./bench_ppe_union.sh

set -euo pipefail

# Same dev-mode semantics as risc0's is_dev_mode(): only 1/true/yes (case-insensitive)
# enable it.
case "$(echo "${RISC0_DEV_MODE:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes)
        echo "ERROR: refusing to benchmark with RISC0_DEV_MODE enabled — numbers would be meaningless."
        exit 1
        ;;
esac

FIXTURES="$(realpath "${PPE_FIXTURES:-ppe_fixtures.bin}")"
COUNTS="${COUNTS:-1 2 4 6 8 10 12 14 16}"
MODES="${UNION_MODES:-1 4}"

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
        output=$(
            PPE_FIXTURES="$FIXTURES" \
            PPE_FIXTURES_COUNT="$count" \
            UNION_PARALLEL="$mode" \
            cargo test -p lee --release --features prove \
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
