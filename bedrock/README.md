# Bedrock Configuration Files for All-in-One run and Integration Tests

## Resolve and run

The node used by Bedrock is resolved from LEZ's locked Cargo dependency. The
resolver accepts a release only when its tag, asset checksum, and commit match
the Cargo-resolved Logos revision; otherwise it builds that exact checkout with
the testing feature. Docker resolution always produces a Linux binary in the
uncommitted `bedrock/.resolved/` directory, using the local controlled Linux
builder when a matching release is unavailable.

Run the local stack with:

```bash
just run-bedrock
```

To resolve the binary without starting Docker:

```bash
just resolve-bedrock-node
```

For direct host-native TF runs, resolve the host binary and pass it explicitly
through TF's existing binary override:

```bash
just resolve-host-bedrock-node

LOGOS_BLOCKCHAIN_NODE_BIN="$PWD/bedrock/.resolved-host/logos-blockchain-node" \
  cargo test -p integration_tests ...
```

Resolving the host binary does not change TF's provider selection on its own.
`LOGOS_BLOCKCHAIN_NODE_BIN` is the TF override that makes direct TF execution
use the resolved host-native binary. The result in `bedrock/.resolved-host/`
is for direct native execution only and must not be used as the payload of the
Docker runtime image. `.resolved/` remains the Linux/Docker path. Both outputs
are derived from the same Cargo-authoritative Logos revision.

The runtime image in `docker-compose.yml` is built from that resolved binary.
Do not update an independent Logos Docker tag or digest. Docker and native
host resolution may produce different platform binaries, but both are tied to
the same Cargo-resolved Logos revision.

## Scripts and tools

The `tools/` directory contains Bedrock provisioning helpers, including the
Cargo-authoritative node resolver and its tests. The `scripts/` directory
contains the runtime configuration entrypoints mounted into the Bedrock
container.

The scripts folder contains the existing configuration entrypoints:

    ```bash
    curl https://raw.githubusercontent.com/logos-blockchain/logos-blockchain/master/testnet/scripts/run_cfgsync.sh >> scripts/run_cfgsync.sh
    curl https://raw.githubusercontent.com/logos-blockchain/logos-blockchain/master/testnet/scripts/run_logos_blockchain_node.sh >> scripts/run_logos_blockchain_node.sh
    chmod +x scripts/*
    ```

    Then in `scripts/run_logos_blockchain_node.sh` update `cfgsync-client` to `logos-blockchain-cfgsync-client` and in `scripts/run_cfgsync.sh` update `cfgsync-server` to `logos-blockchain-cfgsync-server` if it hasn't been fixed already, see <https://github.com/logos-blockchain/logos-blockchain/pull/2092>.

- `cfgsync.yaml` file.

    ```bash
    curl -O https://raw.githubusercontent.com/logos-blockchain/logos-blockchain/master/testnet/cfgsync.yaml
    ```

    Set `logger`, `tracing` and `metrics` to `None`

- `kzgrs_test_params` file.

    ```bash
    curl -O https://raw.githubusercontent.com/logos-blockchain/logos-blockchain/master/tests/kzgrs/kzgrs_test_params
    ```
