set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

# ---- Configuration ----
METHODS_PATH := "program_methods"
TEST_METHODS_PATH := "test_program_methods"
ARTIFACTS := "artifacts"

# Build risc0 program artifacts
build-artifacts:
    @echo "🔨 Building artifacts"
    @for methods_path in {{METHODS_PATH}} {{TEST_METHODS_PATH}}; do \
        echo "Building artifacts for $methods_path"; \
        CARGO_TARGET_DIR=target/$methods_path cargo risczero build --manifest-path $methods_path/guest/Cargo.toml; \
        mkdir -p {{ARTIFACTS}}/$methods_path; \
        cp target/$methods_path/riscv32im-risc0-zkvm-elf/docker/*.bin {{ARTIFACTS}}/$methods_path; \
    done

# Run tests
test:
    @echo "🧪 Running tests"
    RISC0_DEV_MODE=1 cargo nextest run --no-fail-fast

# Run Bedrock node in docker
[working-directory: 'bedrock']
run-bedrock:
    @echo "⛓️ Running bedrock"
    docker compose up

# Run Sequencer
[working-directory: 'sequencer_runner']
run-sequencer:
    @echo "🧠 Running sequencer"
    RUST_LOG=info RISC0_DEV_MODE=1 cargo run --release -p sequencer_runner configs/debug

# Run Indexer
[working-directory: 'indexer/service']
run-indexer mock="":
    @echo "🔍 Running indexer"
    @if [ "{{mock}}" = "mock" ]; then \
        echo "🧪 Using mock data"; \
        RUST_LOG=info RISC0_DEV_MODE=1 cargo run --release --features mock-responses -p indexer_service configs/indexer_config.json; \
    else \
        echo "🚀 Using real data"; \
        RUST_LOG=info RISC0_DEV_MODE=1 cargo run --release -p indexer_service configs/indexer_config.json; \
    fi

# Run Explorer
[working-directory: 'explorer_service']
run-explorer:
    @echo "🌐 Running explorer"
    RUST_LOG=info cargo leptos serve

# Run Wallet
[working-directory: 'wallet']
run-wallet +args:
    @echo "🔑 Running wallet"
    NSSA_WALLET_HOME_DIR=$(pwd)/configs/debug cargo run --release -p wallet -- {{args}}

# Clean runtime data
clean:
    @echo "🧹 Cleaning run artifacts"
    rm -rf sequencer_runner/bedrock_signing_key
    rm -rf sequencer_runner/rocksdb
    rm -rf indexer/service/rocksdb
    rm -rf wallet/configs/debug/storage.json
    rm -rf rocksdb
    cd bedrock && docker compose down -v
