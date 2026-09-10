#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "$docker_arch" in
    amd64|x86_64)
        docker_platform=linux/amd64
        target_platform=linux-x86_64
        ;;
    arm64|aarch64)
        docker_platform=linux/arm64
        target_platform=linux-aarch64
        ;;
    *)
        echo "Unsupported Docker architecture: $docker_arch" >&2
        exit 1
        ;;
esac

image="${BEDROCK_RESOLVER_IMAGE:-logos-execution-zone-ci:local}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
resolver_home=/tmp/lez-bedrock-resolver-home
mkdir -p "$cargo_home/registry" "$cargo_home/git" "$HOME/.cache/logos/blockchain"

echo "Resolving Docker Bedrock node for $target_platform using $image"
docker build \
    --platform "$docker_platform" \
    --file .github/docker/ci.Dockerfile \
    --tag "$image" \
    .

docker run --rm \
    --platform "$docker_platform" \
    --user "$(id -u):$(id -g)" \
    --volume "$repo_root:$repo_root" \
    --volume "$cargo_home/registry:/usr/local/cargo/registry" \
    --volume "$cargo_home/git:/usr/local/cargo/git" \
    --volume "$HOME/.cache/logos/blockchain:$resolver_home/.cache/logos/blockchain" \
    --env HOME="$resolver_home" \
    --env XDG_CACHE_HOME="$resolver_home/.cache" \
    --workdir "$repo_root" \
    --env RUSTFLAGS=-A\ single-use-lifetimes \
    --env RISC0_DEV_MODE=1 \
    "$image" \
    python3 bedrock/tools/resolve_bedrock_node.py \
        --target-platform "$target_platform"
