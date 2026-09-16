FROM rust:1.94.0-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    libclang-dev \
    libssl-dev \
    pkg-config \
    git \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN git config --system --add safe.directory '*'

ENV CARGO_HOME=/cargo
RUN mkdir -p /cargo/registry /cargo/git && chmod -R 0777 /cargo
