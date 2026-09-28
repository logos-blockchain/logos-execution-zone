# Shared build base: cargo-chef toolchain + risc0 r0vm.
#
# This is the single source of truth for the r0vm install that the sequencer
# and indexer service images depend on. It is consumed as a named build context
# called `risc0_base` (the service Dockerfiles start with `FROM risc0_base`).
#
# Wiring:
#   - docker-compose: `build.additional_contexts: { risc0_base: "service:risc0_base" }`
#   - CI: built first and passed via `build-contexts: risc0_base=docker-image://...`
FROM lukemathwalker/cargo-chef:latest-rust-1.98.1-slim-trixie

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    ninja-build \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install r0vm
# Use quick install for x86-64 (risczero provides binaries only for this linux platform)
# Manual build for other platforms (including arm64 Linux)
RUN ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then \
        echo "Using quick install for $ARCH"; \
        curl -L https://risczero.com/install | bash; \
        export PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"; \
        rzup install; \
    else \
        echo "Using manual build for $ARCH"; \
        git clone --depth 1 --branch release-3.0 https://github.com/risc0/risc0.git; \
        git clone --depth 1 --branch risc0-1.94.1 https://github.com/risc0/rust.git; \
        cd /risc0; \
        cargo install --locked --path rzup; \
        rzup build --path /rust rust --verbose; \
        cargo install --locked --path risc0/cargo-risczero; \
    fi
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"
RUN cp "$(which r0vm)" /usr/local/bin/r0vm
RUN test -x /usr/local/bin/r0vm
RUN r0vm --version
