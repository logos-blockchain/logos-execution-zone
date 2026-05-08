# LP-0016: Anonymous Forum with Threshold Moderation

A privacy-preserving forum system built on the **Logos Execution Zone (LEZ)** blockchain, implementing anonymous posting with N-of-M threshold moderation and cryptographic member revocation.

## Overview

This submission implements the complete LP-0016 prize specification: a forum protocol where members can post anonymously with ZK proofs, moderators can issue strikes via threshold consensus, and K accumulated strikes cryptographically reconstruct the offender's secret key — enabling on-chain slashing and retroactive deanonymization of all their historical posts.

### Key Properties

- **Post Unlinkability** — Each post generates a unique tracing tag via `SHA256(NSK ∥ H(M) ∥ Salt)`, making posts computationally indistinguishable from random without the NSK
- **Retroactive Linkability** — Upon K strikes, the reconstructed NSK allows deterministic identification of all historical posts by the slashed member
- **N-of-M Threshold Moderation** — No single moderator can unilaterally strike a member; requires N independent agreements
- **Two-Tier Shamir Secret Sharing** — Per-post shares (Tier 1) feed into a global polynomial (Tier 2) whose root is the member's NSK

## Architecture

```
logos-execution-zone/
├── programs/membership_registry/     # On-chain program logic (guest-safe)
│   └── src/
│       ├── state.rs                  # ForumInstance: admin, K/N/M params, registry, stakes
│       ├── initialize.rs             # Create forum with configurable parameters
│       ├── register.rs               # Register commitment + debit stake
│       ├── slash.rs                  # Revoke membership + confiscate per-member stake
│       └── verify_post.rs            # Registry root validation + tracing tag anti-replay
│
├── program_methods/guest/src/bin/
│   ├── membership_registry.rs        # SPEL guest program (4 instructions)
│   └── forum_membership_proof.rs     # ZK circuit: membership + non-revocation + tag
│
├── logos_moderation_sdk/             # Forum-agnostic moderation library
│   └── src/
│       ├── clients/
│       │   ├── member.rs             # prepare_post(), SSS share encryption, tracing tags
│       │   ├── moderator.rs          # issue_strike(), share decryption, Schnorr signing
│       │   └── aggregator.rs         # reconstruct_strike() (Tier 1), reconstruct_nsk() (Tier 2)
│       ├── crypto/
│       │   ├── sss.rs                # Shamir Secret Sharing over GF(256) via sharks crate
│       │   └── signature/            # BIP-340 Schnorr signatures
│       ├── types.rs                  # PostPayload, EncryptedSharePerPost, ModerationCertificate
│       └── wasm_bindings.rs          # WASM bridge for Basecamp App
│
├── integration_tests/tests/
│   └── forum.rs                      # Full lifecycle E2E test
│
├── docs/
│   └── protocol.md                   # Formal protocol specification
│
└── demo_e2e.sh                       # End-to-end demonstration script
```

## On-Chain Program: Membership Registry

The membership registry is implemented as a **SPEL framework** guest program, compiled to RISC-V and executed inside the RISC Zero ZKVM. It exposes four instructions:

| Instruction | Description | Access Control |
|-------------|-------------|----------------|
| `initialize_forum` | Creates forum instance with K, N, M parameters | Signer becomes admin |
| `register_member` | Registers commitment to Merkle tree, debits stake from member balance | Signer (member) |
| `verify_post` | Validates registry root consistency and records tracing tag (anti-replay) | Permissionless |
| `slash_member` | Revokes membership given reconstructed NSK, confiscates stake to admin | Admin only |

### Account Model

Forum state is stored in a PDA account per forum instance (`pda = ["forum", forum_id]`), enabling multiple independent forum instances per deployment. It contains:

- `admin_pubkey: [u8; 32]` — Admin identity for slash authorization
- `k_strikes / n_moderators / m_moderators` — Configurable threshold parameters
- `registry: MerkleTree` — Sparse Merkle Tree of member commitments
- `registered_commitments: Vec<[u8; 32]>` — Raw commitment bytes for slash verification
- `revoked_commitments: Vec<[u8; 32]>` — Blacklist of slashed commitments
- `member_stakes: Vec<([u8; 32], u64)>` — Per-member stake tracking
- `used_tracing_tags: Vec<[u8; 32]>` — Anti-replay set for post verification

### ZK Membership Proof Circuit

The `forum_membership_proof` guest binary is a standalone ZK circuit that proves three properties without revealing the poster's identity:

1. **Inclusion** — The member's commitment exists in the registry Merkle tree
2. **Non-revocation** — The commitment is not in the blacklist
3. **Tag integrity** — The tracing tag was correctly derived from the member's NSK

## Off-Chain Library: logos_moderation_sdk

A standalone, forum-agnostic Rust crate that handles all off-chain cryptographic operations. It operates on abstract byte identifiers and makes no assumptions about the forum implementation.

### Public API

```rust
// Member: prepare a post with ECDH-encrypted SSS shares
let mut member = MemberClient::new(nsk, k_strikes);
let post = member.prepare_post(&message, &post_salt, &moderator_pubkeys, n_threshold)?;
// post.tracing_tag    — [u8; 32], unique per-post identifier
// post.encrypted_shares — one per moderator, ECDH-encrypted Shamir share

// Moderator: decrypt share, sign, and issue strike certificate
let moderator = ModeratorClient::new(private_key);
let certificate = moderator.issue_strike(post.tracing_tag, &post.encrypted_shares[mod_index], mod_index)?;

// Aggregator: reconstruct per-post secret (Tier 1), then NSK (Tier 2)
let aggregator = SlashAggregator::new(n_threshold, k_strikes, &moderator_pubkeys);
let s_post = aggregator.reconstruct_strike(&post.tracing_tag, &certificates)?;
// ... after K strikes:
let nsk = aggregator.reconstruct_nsk(&accumulated_strikes)?;
```

### WASM Bindings

All three clients are exposed via `wasm-bindgen` for use in the Logos Basecamp web application:
- `WasmMemberClient` — Post preparation and proof generation
- `WasmModeratorClient` — Strike issuance and certificate creation  
- `WasmSlashAggregator` — Strike/NSK reconstruction

## Prerequisites

- Rust toolchain (edition 2021+)
- [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install) (`rzup install`)
- Docker (for reproducible builds via `just build-artifacts`)
- [just](https://github.com/casey/just) command runner

## Build

### Reproducible Build (Docker)

```bash
just build-artifacts
```

This produces deterministic ELF binaries in `artifacts/program_methods/` with verified Image IDs.

### Development Build (Fast)

```bash
RISC0_DEV_MODE=1 cargo build -p program_methods --release
```

### Verify Compilation

```bash
RISC0_DEV_MODE=1 cargo check -p programs
```

## Run Tests

```bash
# Unit tests
RISC0_DEV_MODE=1 RISC0_SKIP_BUILD=1 cargo test -p membership_registry
RISC0_DEV_MODE=1 RISC0_SKIP_BUILD=1 cargo test -p logos_moderation_sdk

# Full E2E lifecycle test (dev mode — fast, ~1.3s)
HOST_CC=gcc RISC0_DEV_MODE=1 cargo test -p integration_tests -- test_forum_e2e_full_lifecycle --nocapture

# Full E2E lifecycle test (real ZK proofs — ~98s on i7-6600U)
HOST_CC=gcc cargo test --release -p integration_tests -- test_forum_e2e_full_lifecycle --nocapture
```

> **Note:** `HOST_CC=gcc` is required on Linux to prevent the risc0 C toolchain from being used when compiling host-side `ring` cryptography dependencies.

## Generate IDL

First install the SPEL CLI (requires the [spel repository](https://github.com/logos-co/spel)):

```bash
cargo install --path /path/to/spel --bin spel --force
```

Then generate the IDL:

```bash
spel generate-idl program_methods/guest/src/bin/membership_registry.rs
```

## Demo

```bash
chmod +x demo_e2e.sh
./demo_e2e.sh
```

The demo script exercises the full lifecycle:
1. Initialize a forum instance (K=3, N=3, M=5)
2. Register a member with commitment and stake
3. Verify a post (registry root + tracing tag)
4. Slash a member (admin-authorized NSK submission)

## Protocol Specification

See [docs/protocol.md](docs/protocol.md) for the formal specification covering:
- Unlinkability argument with formal proofs
- Retroactive deanonymization property
- N-of-M threshold security model
- Two-tier collusion resistance analysis
- Game-theoretic deterrence mechanisms

## Success Criteria Mapping

| Criterion | Status | Implementation |
|-----------|--------|----------------|
| Member register + stake + anonymous post proof | ✅ | `register_member` instruction + `forum_membership_proof` circuit |
| Post unlinkability | ✅ | SHA256(NSK ∥ H(M) ∥ Salt) with per-post random salt |
| Retroactive linkability upon slash | ✅ | NSK exposure enables deterministic tag recomputation |
| N-of-M moderation certificates | ✅ | `ModeratorClient` + `SlashAggregator` in SDK |
| K strikes → slash transaction | ✅ | `reconstruct_nsk()` → `slash_member` instruction |
| Revoked commitment → post rejection | ✅ | Blacklist check in ZK circuit |
| Parameterisable K and N-of-M | ✅ | Set at `initialize_forum` time |
| Forum-agnostic library | ✅ | `logos_moderation_sdk` crate |
| IDL via SPEL framework | ✅ | `#[lez_program]` with `#[instruction]` annotations |
| WASM bindings for Basecamp | ✅ | `WasmMemberClient`, `WasmModeratorClient`, `WasmSlashAggregator` |

## License

See repository root for license information.
