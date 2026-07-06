# Image behind the `container:` of the CI jobs. Everything the jobs used to
# install per-run is baked in here instead, so a CI run no longer asks the risc0
# install servers for anything.
#
# The image tag is a hash of this file plus rust-toolchain.toml, so editing
# either rebuilds the image on the PR that changes it. See ci-image.yml.
#
# Keep the base tag in sync with rust-toolchain.toml.
FROM rust:1.94.0-trixie

# GitHub sets HOME=/github/home inside container jobs, which hides anything we
# bake into the image's ~. rzup defaults to $HOME/.risc0, so pin it to a fixed
# path; RUSTUP_HOME and CARGO_HOME already point at /usr/local from the base
# image, and rzup honours all three.
ENV RISC0_HOME=/usr/local/risc0
ENV PATH=/usr/local/risc0/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    libclang-dev \
    libssl-dev \
    pkg-config \
    libpcsclite-dev \
    curl \
    git \
    jq \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# The runner pre-creates the workspace as another uid, so git in a container job
# calls it dubious. checkout's own fix is --global, which only holds while HOME
# still points at the gitconfig it wrote; --system holds regardless.
RUN git config --system --add safe.directory '*'

# The base image already has this toolchain at the minimal profile, so the
# `profile = "default"` in rust-toolchain.toml is a no-op here: rustup sees the
# toolchain as installed and never applies it. Add what the jobs need by hand.
COPY rust-toolchain.toml /tmp/toolchain/rust-toolchain.toml
RUN cd /tmp/toolchain \
    && rustup toolchain install \
    && rustup component add clippy rustfmt \
    && rm -rf /tmp/toolchain

# For `cargo +nightly fmt` in the fmt-rs job.
RUN rustup toolchain install nightly --profile minimal --component rustfmt

# The bootstrap script only ever drops rzup in $HOME/.risc0/bin, so run it
# against the build-time HOME and keep just the binary. rzup itself then honours
# RISC0_HOME and installs each component under /usr/local.
#
# Versions pinned to the set currently validated in local dev (`rzup show`);
# bare `rzup install` would float all four default components to latest. r0vm
# and cargo-risczero track each other and the risc0-zkvm crate version.
RUN curl -L https://risczero.com/install | bash \
    && mv /root/.risc0/bin/rzup /usr/local/bin/rzup \
    && rm -rf /root/.risc0 \
    && rzup install rust 1.94.1 \
    && rzup install cpp 2024.1.5 \
    && rzup install r0vm 3.0.5 \
    && rzup install cargo-risczero 3.0.5

# Copying docker. Static Go binaries, so the alpine-built ones run fine here.
COPY --from=docker:29.6.1-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29.6.1-cli /usr/local/libexec/docker/cli-plugins/docker-compose \
     /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=docker:29.6.1-cli /usr/local/libexec/docker/cli-plugins/docker-buildx \
     /usr/local/libexec/docker/cli-plugins/docker-buildx

# Prebuilt binaries; compiling these from source would dominate the image build.
# Versions pinned so a rebuild of the same image ships the same tools.
ENV BINSTALL_VERSION=1.21.0
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
      https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall --no-confirm \
        cargo-nextest@0.9.140 \
        taplo-cli@0.10.0 \
        cargo-machete@0.9.2 \
        cargo-deny@0.20.2 \
        just@1.56.0

# Smoke-test every tool the jobs use. A bad install should fail here, not later
# in some CI job that reuses this cached image. pyo3's `auto-initialize` links
# libpython, and the base image ships python3 without it, so check the .so too.
RUN cargo --version \
    && cargo +nightly fmt --version \
    && cargo clippy --version \
    && ls /usr/lib/*/libpython3*.so \
    && r0vm --version \
    && cargo risczero --version \
    && cargo nextest --version \
    && taplo --version \
    && cargo machete --version \
    && cargo deny --version \
    && just --version \
    && docker --version \
    && docker compose version \
    && docker buildx version
