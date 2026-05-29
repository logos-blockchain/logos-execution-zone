FROM rust:1.94.0-trixie AS builder

# Install cargo-binstall, which makes it easier to install other
# cargo extensions like cargo-leptos
RUN wget https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz
RUN tar -xvf cargo-binstall-x86_64-unknown-linux-musl.tgz
RUN cp cargo-binstall /usr/local/cargo/bin

# Install required tools
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends clang

# Install cargo-leptos
RUN cargo binstall cargo-leptos -y

# Add the WASM target
RUN rustup target add wasm32-unknown-unknown

# Make an /explorer_service dir, which everything will eventually live in
RUN mkdir -p /explorer_service
WORKDIR /explorer_service
COPY . .

# Build the app
RUN --mount=type=cache,target=/usr/local/cargo/registry/index \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/explorer_service/target \
    cargo leptos build --release -vv \
    && cp /explorer_service/target/release/explorer_service /usr/local/bin/explorer_service \
    && cp -r /explorer_service/target/site /explorer_service/site_output

FROM debian:trixie-slim AS runtime
WORKDIR /explorer_service
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

# Copy the server binary to the /explorer_service directory
COPY --from=builder /usr/local/bin/explorer_service /explorer_service/

# /target/site contains our JS/WASM/CSS, etc.
COPY --from=builder /explorer_service/site_output /explorer_service/site

# Copy Cargo.toml as it’s needed at runtime
COPY --from=builder /explorer_service/Cargo.toml /explorer_service/

# Set any required env variables
ENV RUST_LOG="info"
ENV LEPTOS_SITE_ADDR="0.0.0.0:8080"
ENV LEPTOS_SITE_ROOT="site"
ENV INDEXER_RPC_URL="http://localhost:8779"
EXPOSE 8080

# Run the server
CMD ["/explorer_service/explorer_service"]
