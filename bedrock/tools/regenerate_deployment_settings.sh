#!/usr/bin/env bash
# Regenerates bedrock/deployment-settings*.yaml from bedrock/genesis/ with the genesis tool of the
# Cargo-resolved Logos revision. Run `just resolve-bedrock-node` first: it builds the image and
# fetches the checkout used here.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

image="${BEDROCK_RESOLVER_IMAGE:-lez-bedrock-resolver:local}"
revision="$(python3 -c 'import json; print(json.load(open("bedrock/.resolved/metadata.json"))["resolved_sha"])')"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
checkout="$(find "$cargo_home/git/checkouts" -maxdepth 2 -type d -path "*/logos-blockchain-*/${revision:0:7}" | head -n 1)"
[ -n "$checkout" ] || { echo "No Cargo checkout of Logos revision $revision" >&2; exit 1; }
target="$repo_root/target/bedrock-node"

in_docker() {
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "$repo_root:$repo_root" \
        --volume "$cargo_home/registry:/cargo/registry" \
        --volume "$cargo_home/git:/cargo/git" \
        --env CARGO_HOME=/cargo \
        --env HOME=/tmp/lez-bedrock-resolver-home \
        --env CARGO_TARGET_DIR="$target" \
        --env RUSTFLAGS=-A\ single-use-lifetimes \
        "$@"
}

in_docker --workdir "/cargo/git/checkouts/${checkout#"$cargo_home/git/checkouts/"}" "$image" \
    cargo build --locked --release -p logos-blockchain-tools --bin logos-blockchain-tools-genesis

settings="$(mktemp)"
in_docker --workdir "$repo_root/bedrock" "$image" \
    "$target/release/logos-blockchain-tools-genesis" ceremony \
    --inscription-params genesis/inscribe.yaml \
    --stake-holders genesis/stakeholders.yaml \
    --providers genesis/providers.yaml \
    --template genesis/era-template.yaml >"$settings"

mv "$settings" bedrock/deployment-settings.yaml
sed 's/security_param: 3$/security_param: 10/' bedrock/deployment-settings.yaml \
    >bedrock/deployment-settings-slow-finality.yaml
echo "Regenerated bedrock/deployment-settings.yaml and its slow-finality variant"
