# Builder stage
FROM risc0_base AS builder

WORKDIR /indexer_service

# Comma-separated extra cargo features. Defaults to `prove`, which selects the
# in-process guest executor with a memoized memory image instead of spawning an
# r0vm subprocess per execution.
ARG FEATURES="prove"

COPY . .

# `target` is a cache mount, so rebuilds only recompile what changed; copy the binary out of it.
RUN --mount=type=cache,id=indexer-cargo-registry-index,target=/usr/local/cargo/registry/index \
  --mount=type=cache,id=indexer-cargo-registry-cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,id=indexer-cargo-git,target=/usr/local/cargo/git \
  --mount=type=cache,target=/indexer_service/target \
  cargo build --release ${FEATURES:+--features "$FEATURES"} --bin indexer_service \
  && strip /indexer_service/target/release/indexer_service \
  && cp /indexer_service/target/release/indexer_service /usr/local/bin/indexer_service

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  curl \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash indexer_service_user && \
  mkdir -p /indexer_service /etc/indexer_service /var/lib/indexer_service && \
  chown -R indexer_service_user:indexer_service_user /indexer_service /etc/indexer_service /var/lib/indexer_service

# Copy binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /usr/local/bin/indexer_service /usr/local/bin/indexer_service

# Copy r0vm binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /usr/local/bin/r0vm /usr/local/bin/r0vm

VOLUME /var/lib/indexer_service

# Expose default port
EXPOSE 8779

# Health check. JSON-RPC errors come back as HTTP 200, so require a `result`.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost:8779 \
  -H "Content-Type: application/json" \
  -d "{ \
  \"jsonrpc\": \"2.0\", \
  \"method\": \"checkHealth\", \
  \"params\": {}, \
  \"id\": 1 \
  }" | grep -q '"result"' || exit 1

# Run the application
ENV RUST_LOG=info,risc0_zkvm=warn,kameo=warn,jsonrpsee_server=warn

# Set explicit location for r0vm binary
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

USER indexer_service_user

WORKDIR /indexer_service
CMD ["indexer_service", "/etc/indexer_service/indexer_config.json", "--data-dir", "/var/lib/indexer_service"]
