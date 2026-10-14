# DevOps refactors

Goal: an operator deploys LEZ with about 5 env vars, one mounted secret and one data volume. Everything else is baked into the image or is a code default.

## Where we are

None of the binaries can configure themselves from the environment, so configuration logic has spread to other places:

- Five or six hand-edited JSON config variants (`lez/configs/docker-all-in-one`, `lez/{sequencer,indexer}/service/configs/{debug,docker}`, devnet).
- Compose files that override `entrypoint:` and pull values out of the JSON with `grep | cut` (`docker-compose.devnet.yml` `x-await-channel`).
- Logic that exists only in the `Justfile`, `tools/run_sequencer.sh` and the Python tools: channel checks, staking and joining, port allocation.
- No config in any image. The sequencer and indexer images crash unless a JSON file is mounted at a fixed path.

Operators also have to keep these in sync by hand:

- Between the sequencer and indexer configs: `channel_id`, `cross_zone` and the bedrock URL. The key names even differ: `bedrock_config.node_url` vs `bedrock_config.addr`, and a nested vs top-level `channel_id`.
- Across every sequencer: `channel_params` and `genesis`.

logos-blockchain gets the binary side right:

- Every flag has an `env =` binding.
- Genesis is embedded with `include_bytes!` and can be overridden with `--deployment`.
- It has `init-config` / `generate-key` subcommands.
- Config parsing is strict and there is a `--check-config` mode.

Copy that. Don't copy its compose files, which have the same problems as ours.

## Where settings should live

| Bucket | Owner | Where | Contents |
|---|---|---|---|
| 1. Network definition (identical on every node of a network) | devs | One committed file per network (`local`, `devnet`, `testnet`), embedded in the binary and selected with `--network` | `channel_id`, `channel_params`, `genesis` (including `stake_sequencer` entries), `cross_zone`, `funding_key`, bootstrap peers |
| 2. Tuning | devs | Serde defaults; the config file becomes an optional override | `max_num_tx_in_block`, `mempool_max_size`, `block_create_timeout`, `retry_pending_blocks_timeout`, `consensus_info_polling_interval` |
| 3. Per deployment | infra | Env vars | bedrock URL, ports, bind address, data dir, `allow_chain_reset`, log level |
| 4. Secrets | infra | Mounted file, path given by env | signing key(s), bedrock basic-auth password (today plaintext in JSON) |

Because the sequencer and indexer read the same embedded network file, they can't drift apart. `tools/devnet_configs` turns into the generator for network files. Adding a sequencer then means:

1. Infra generates a key and hands over the public key only.
2. Devs add the stake entry to `networks/<net>.json`.
3. A release is cut.

## CLI and env convention

- Every flag is `--kebab-name` with `env = "<SERVICE>_KEBAB_NAME"` (prefix `SEQUENCER_`, `INDEXER_`, `EXPLORER_`).
- No bare `--port` on a service that listens on more than one port.
- One unit test per binary walks `Args::command().get_arguments()` and asserts each arg's env name follows the rule.
- A per-service prefix rather than a shared `LEZ_` one: a shared `LEZ_RPC_PORT` would mean 3040 in one container and 8779 in another, which breaks as soon as it lands in a shared `.env`.

Target sequencer surface:

| Flag | Env | Default |
|---|---|---|
| `--network` | `SEQUENCER_NETWORK` | `local` |
| `--network-file` | `SEQUENCER_NETWORK_FILE` | overrides the embedded file |
| `--bedrock-url` | `SEQUENCER_BEDROCK_URL` | `http://localhost:18080` |
| `--bedrock-password-file` | `SEQUENCER_BEDROCK_PASSWORD_FILE` | none |
| `--data-dir` (was `--home`) | `SEQUENCER_DATA_DIR` | `/var/lib/sequencer_service` in the image |
| `--signing-key-file` | `SEQUENCER_SIGNING_KEY_FILE` | `<data-dir>/bedrock_signing_key` |
| `--generate-key` | `SEQUENCER_GENERATE_KEY` | true only on `local`; otherwise a missing key is a hard error |
| `--listen-address` | `SEQUENCER_LISTEN_ADDRESS` | `0.0.0.0` |
| `--rpc-port` (was `--port`) | `SEQUENCER_RPC_PORT` | 3040 |
| `--metrics-port` (was `metrics_address` in config) | `SEQUENCER_METRICS_PORT` | 9000 |
| `--gossip-port` | `SEQUENCER_GOSSIP_PORT` | a fixed port; today it is `udp/0`, random and impossible to firewall or map |
| `--config` (was positional) | `SEQUENCER_CONFIG` | optional tuning overrides |

The indexer gets the same shape:

- `INDEXER_` prefix, RPC port 8779.
- A new `--listen-address`; the bind address is hardcoded `0.0.0.0` today.
- `INDEXER_ALLOW_CHAIN_RESET`, default `false`.

The explorer:

- `INDEXER_RPC_URL` becomes `EXPLORER_INDEXER_URL`.
- Add `--http-port` / `EXPLORER_HTTP_PORT`, applied over `LEPTOS_SITE_ADDR`.

No config-layering crate is needed: clap `env` plus serde defaults covers it.

## Compose: one file shape for every environment

- `compose.yml` is the reference deployment, driven only by env, with `depends_on: condition: service_healthy`.
- `profiles: [local]` covers bedrock, monitoring and the `build:` blocks.
- `.env.local` is committed. `.env.devnet` and `.env.testnet` are templates infra fills in, mostly image tags and URLs.
- Infra runs `docker compose --env-file .env.testnet up`, or translates the file one-to-one to Helm.
- The `Justfile` stays for dev ergonomics. Rule: nothing deployment-relevant lives only in the `Justfile` or a script.

## CI/CD

- **Build once, promote by digest:** merge to `main`, then `devnet`, then `testnet`. One binary serves every network, since network files are embedded.
- **Config validation:** `sequencer_service check --network <net>` and `deny_unknown_fields`, run in CI.
- **Compose smoke test:** `docker compose up --wait`, send one transaction, tear down.
- **Bedrock image:** publish one at the rev pinned in `Cargo.toml`, replacing the `just resolve-bedrock-node` step. A fresh checkout can't build the bedrock image today.
- **Image variants:** keep `sequencer_service` and `-standalone`. Drop `-mdns`, or make mDNS a runtime flag.
- **Pinning:** pin `cargo-chef:latest-…`, `curl risczero.com/install | bash`, and `cargo-binstall releases/latest`.
- **Deploy step itself:** that is infra's call. We stop at "a digest plus a reference compose file".

## Phases

### 1. Quick fixes

- [x] The indexer ignores SIGTERM, so `docker stop` SIGKILLs it with RocksDB open.
- [x] The indexer healthcheck calls `get_schema`; the method is `getSchema`. No healthcheck checked the JSON-RPC result, and an RPC error is still HTTP 200.
- [x] The compose devnet image is built with `FEATURES: mdns`, which drops `prove`. It now builds `prove,mdns`, matching the published `sequencer_service-mdns`.
- [x] Remove the dead `bedrock_config.backoff` key from the sequencer configs.
- [x] Write generated keys with mode `0600` and warn loudly when one is generated.
- [x] The explorer image: non-root user and a healthcheck.
- [x] The indexer image: set `RISC0_SERVER_PATH` like the sequencer image does.

### 2. CLI/env surface

- [ ] Env bindings and port renames as above, plus the naming test.
- [ ] Optional `--config`, with serde defaults for bucket 2 (`default_channel_params()` exists but isn't wired up; see `// TODO: Provide default values`).
- [ ] `deny_unknown_fields` on the sequencer and indexer configs. Note that `lez-indexer-module/config/indexer_config.json` still carries `bedrock_config.backoff`; drop it there first.
- [ ] `--signing-key-file`, and a hard error on a missing key outside `local`.
- [ ] Secrets via `*_FILE` env, not plaintext JSON.

### 3. Network files

- [ ] `networks/{local,devnet,testnet}.json`, embedded in the binary and shared by the sequencer and indexer.
- [ ] Generalise `tools/devnet_configs` to generate them.

### 4. Compose and CI

- [ ] Single `compose.yml` plus profiles and `.env.*`; delete the per-service compose files and `docker-compose.override.yml`.
- [ ] Smoke test, digest promotion, bedrock image, pinned build inputs.

### 5. Ops logic into the binary

- [ ] The sequencer waits for the channel itself, replacing the compose `x-await-channel` entrypoint.
- [ ] Ship `submit_stake` and `bedrock_pubkey` in the sequencer image.
- [ ] `GET /health` via jsonrpsee `ProxyGetRequestLayer` mapped to `checkHealth` (closes TODO #244).

## Open questions for infra

- Kubernetes or compose on VMs? This decides whether secrets are `/run/secrets` files or k8s Secrets; `*_FILE` env vars work with both.
- JSON logs? Today logging is `env_logger` text only.
- Who runs the L1 nodes for devnet and testnet, and who holds the secret behind `funding_key`? It is committed in plaintext in `bedrock/node-config.yaml`, which is fine for local only.
- Is `GENESIS_STAKE_FUNDING_KEY = [9; 32]` (`lez/sequencer/core/src/lib.rs`) meant for real networks?
- Every committed indexer config sets `allow_chain_reset: true`. That is fine locally; it must never be copied to a real network. Phase 2 moves it to `INDEXER_ALLOW_CHAIN_RESET`, default `false`.
