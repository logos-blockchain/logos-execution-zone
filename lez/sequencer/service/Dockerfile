# Builder stage
FROM risc0_base AS builder

# The wallet behind `stake`/`unstake` pulls in keycard support, which links libpcsclite.
# Installed here, not in risc0_base, so the base's r0vm layer stays cached.
RUN apt-get update && apt-get install -y libpcsclite-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /sequencer_service

# Build argument to enable standalone feature (defaults to false)
ARG STANDALONE=false
# Comma-separated extra cargo features, e.g. FEATURES=mdns for LAN peer discovery.
# Defaults to `prove`, which selects the in-process guest executor with a memoized
# memory image instead of spawning an r0vm subprocess per execution.
ARG FEATURES="prove"

COPY . .

# `target` is a cache mount, so rebuilds only recompile what changed; copy the binary out of it.
RUN --mount=type=cache,id=sequencer-cargo-registry-index,target=/usr/local/cargo/registry/index \
  --mount=type=cache,id=sequencer-cargo-registry-cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,id=sequencer-cargo-git,target=/usr/local/cargo/git \
  --mount=type=cache,target=/sequencer_service/target \
  features="$FEATURES"; \
  if [ "$STANDALONE" = "true" ]; then features="${features:+$features,}standalone"; fi; \
  cargo build --release ${features:+--features "$features"} --bin sequencer_service \
  && strip /sequencer_service/target/release/sequencer_service \
  && cp /sequencer_service/target/release/sequencer_service /usr/local/bin/sequencer_service

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  curl \
  libpcsclite1 \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash sequencer_service_user && \
  mkdir -p /sequencer_service /var/lib/sequencer_service && \
  chown -R sequencer_service_user:sequencer_service_user /sequencer_service /var/lib/sequencer_service

# Copy binary from builder
COPY --from=builder --chown=sequencer_service_user:sequencer_service_user /usr/local/bin/sequencer_service /usr/local/bin/sequencer_service

# Copy r0vm binary from builder
COPY --from=builder --chown=sequencer_service_user:sequencer_service_user /usr/local/bin/r0vm /usr/local/bin/r0vm

VOLUME /var/lib/sequencer_service

# Expose default ports
EXPOSE 3040
EXPOSE 9000

# Defaults for `start`, as env so a deployment can override each one the same way.
ENV SEQUENCER_HOME=/var/lib/sequencer_service
ENV SEQUENCER_RPC_LISTEN_ADDRESS=0.0.0.0:3040
ENV SEQUENCER_METRICS_LISTEN_ADDRESS=0.0.0.0:9000

# Follows the ops server when SEQUENCER_METRICS_LISTEN_ADDRESS is overridden.
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -fsS -o /dev/null "http://$SEQUENCER_METRICS_LISTEN_ADDRESS/health" || exit 1

# Run the application
ENV RUST_LOG=info,risc0_zkvm=warn,kameo=warn

# Set explicit location for r0vm binary
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

USER sequencer_service_user

WORKDIR /sequencer_service
CMD ["sequencer_service", "start"]
