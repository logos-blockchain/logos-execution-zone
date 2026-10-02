# LEZ Specifications (for review)

**Logos Execution Zone (LEZ)** is an L2 blockchain that uses LEE as its state machine. LEE defines accounts, programs, transactions, and how they execute. LEZ adds block production, L1 settlement, fees, and query infrastructure, using the interfaces LEE exposes to a host chain.

## System Components

```text
Wallet ──► Sequencer (RPC: submit transactions, read state)
              │  ▲
              │  └── p2p gossip with other committee sequencers (optional)
              │
              ▼  publish blocks
           Bedrock (L1) ──► Sequencers follow the channel: peer blocks, finality, deposits, turns
              │
              ▼  finalized blocks
           Indexer (read-only) ◄── Explorer, other clients (RPC, subscriptions)
```

### Sequencer

The sequencers are the only writers of the zone's channel. A channel on Bedrock can have several accredited sequencers, each backed by a stake; together these sequencers form the *committee*. Bedrock hands out posting turns among them in round robin. Only the sequencer holding the turn produces a block. Each sequencer collects transactions (from users over RPC, from peers over optional gossip, and from its own records of bridge deposits and cross-zone deliveries), produces blocks on its turns, and publishes them to Bedrock. Every sequencer also follows the channel: it applies the blocks its peers publish and tracks which blocks Bedrock has finalized. This keeps a live copy of LEE state, which the sequencer uses to validate transactions before including them in a block and serves over RPC.

### Indexer

The indexer is read-only. It consumes finalized blocks from Bedrock, validates and applies them to reconstruct LEE state, and serves RPC queries and subscriptions.

### Bedrock

Bedrock is the L1 chain. It acts as the canonical ordering layer and settlement mechanism. Both sequencer and indexer communicate with Bedrock through the zone-sdk library.

### Clients

- **Wallet.** Talks to the sequencer RPC: it submits transactions, reads account state, and sizes `max_fee` from its configured `gas_limit` (by default against 8× the genesis minimum base fee; `getFeeState` gives the next block's range). It builds and proves privacy-preserving transactions locally, so the sequencer only verifies proofs, and it discovers its private notes by scanning blocks (`getBlockRange`) for matching view tags. Key derivation and note encryption follow LEE's key protocol (see [`lee-specs.md`](lee-specs.md)). The sequencer's block, transaction, and account queries remain until the wallet reads from the indexer.
- **Explorer.** A web interface over the indexer RPC; it holds no state of its own.

## LEZ basic types and constants

LEE types and constants used in this document are defined in [`lee-specs.md`](lee-specs.md#lee-v03-basic-types-and-constants): `AccountId`, `ProgramId`, `Nonce`, `Balance`, `Gas`, `Fee`, `Cycles`, `BlockId`, `Timestamp`, `GENESIS_BLOCK_ID`, `Account`, `AccountData`, `ShardData`, `ProgramShardSelector`, `InstructionData`, `EffectData`, `Signature`, `PublicKey`, `Proof`, `Commitment`, `CommitmentSetDigest`, `Nullifier`, `MembershipProof`, `EncryptedAccountData`, `EphemeralPublicKey`, `Ciphertext`, `ViewTag`, `BlockValidityWindow`, `TimestampValidityWindow`, `ProgramImageClaim`, `DeferredPublicEffect`, `PublicActionWithID`, `PrivateAction`, `ProgramEvent`, and `V03State`. `Balance`, `Gas`, `Fee`, and `Cycles` are restated below.

```rust
// ---- Identifiers ----
/// A block hash or transaction hash.
type HashType = [u8; 32];
type BlockHash = HashType;
/// A Bedrock channel id.
type ChannelId = [u8; 32];
/// A zone's id: its Bedrock channel id.
type ZoneId = ChannelId;
/// A sequencer's Bedrock identity. Holds only a valid Ed25519 public key.
struct SequencerKey([u8; 32]);
/// An event selector: by convention the first 8 bytes of SHA256("<program>::<EventName>").
type Selector = [u8; 8];

// ---- Metering and fees (defined by LEE; restated for the Fees section) ----
/// Native token amount, stored in the account's native balance shard.
type Balance = u128;
/// Gas amount (execution or storage work).
type Gas = u64;
/// Base-fee price or tip, in atomic units.
type Fee = u64;
/// Raw zkVM cycle count or budget.
type Cycles = u64;

// ---- Blocks ----
/// Bytes of `max_block_size` reserved for the header and the forced fee and clock transactions.
const BLOCK_OVERHEAD: u64 = 2_048;

// ---- Fees (see Fees) ----
const TARGET_GAS_EXEC: Gas = 5_000_000;
const MAX_GAS_EXEC: Gas = 2 * TARGET_GAS_EXEC;
const TARGET_GAS_STOR: Gas = 500_000;
const MAX_GAS_STOR: Gas = 2 * TARGET_GAS_STOR;
const D_EXEC: u64 = 8;
const D_STOR: u64 = 8;
const BASE_FEE_EXEC_MIN: Fee = 8;
const BASE_FEE_STOR_MIN: Fee = 8;
const BASE_FEE_EXEC_MAX: Fee = u64::MAX / MAX_GAS_EXEC;
const BASE_FEE_STOR_MAX: Fee = u64::MAX / MAX_GAS_STOR;
const SMOOTHING_WINDOW: usize = 50;

// ---- Cross-zone (see Cross-zone messaging) ----
const MAX_DISPATCHES_PER_BLOCK: usize = 16;
const RETIRE_DISPATCH_AFTER_FAILURES: u32 = 3;
const MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES: usize = 256;   // currently fixed; slated to become configurable

// ---- Indexer (see Indexer Flow) ----
const APPLY_RETRY_LIMIT: u32 = 3;   // apply attempts before a possibly transient failure parks

// ---- RPC ----
const REQUEST_BODY_MAX_SIZE: usize = 10 * 1024 * 1024;   // sequencer and indexer (jsonrpsee default)
const MAX_EVENT_QUERY_BLOCK_SPAN: u64 = 1_000;           // indexer getEvents
const MAX_BLOCK_RANGE_LEN: usize = 1_024;                // sequencer getBlockRange
```

## Data Types

Several of these types (`AccountId`, `ProgramId`, `Nonce`, `Balance`, `Account`) are defined by LEE, not LEZ. They are documented here only because they appear on LEZ wire formats and RPC surfaces; LEE remains their source of truth.

### `AccountId`

- **Representation**: `[u8; 32]`
- **Derivation** (public accounts): `SHA256("/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00" || PublicKey)` where `PublicKey` is the 32-byte secp256k1 x-only public key (BIP340)
- Programs are also addressed by an `AccountId` (their `program_account_id`). LEZ builtins live at a name-derived address, `SHA256("/LEE-BuiltinProgram/v1/AccountId" || name)`.
- **JSON encoding**: Base58
- **Borsh encoding**: Raw 32 bytes

### `HashType` / `BlockHash`

- **Representation**: `[u8; 32]`
- **JSON encoding**: Hex string (lowercase)
- **Borsh encoding**: Raw 32 bytes

### `BlockId`

- **Representation**: `u64`
- **Genesis value**: `1`
- **JSON encoding**: Decimal integer

### `ProgramId`

- **Representation**: `[u32; 8]` (8 little-endian u32 values)
- A program's RISC Zero image ID. It does not address a program: transactions name the program's `AccountId`.
- **Borsh encoding**: 32 bytes LE
- **JSON encoding**: context-dependent — see Serialization section

### `Nonce`

- **Representation**: `u128`
- **JSON encoding**: Decimal integer
- **Borsh encoding**: 16 bytes little-endian

### `Balance`

- **Representation**: `u128`
- **JSON encoding**: Decimal integer
- Stored in the account's native-token shard (16 bytes little-endian; an absent shard means `0`), not as an account field.

### `Account`

```rust
struct Account {
    nonce: Nonce,                                   // u128
    data: AccountData,
}

struct AccountData {
    shards: BTreeMap<AccountId, ShardData>,         // one shard per program; each max 100 KiB
}
```

The native balance is the shard keyed by the native token program's address (`[0u8; 32]`).

### `ProgramShardSelector`

```rust
struct ProgramShardSelector {
    account_id: AccountId,           // the account
    program_account_id: AccountId,   // which program's shard of it
}
```

## Serialization

### Binary format (Borsh)

All data structures use **Borsh** serialization for:
- Block publication to Bedrock
- Block reception from Bedrock
- Storage on disk, except the zone-sdk checkpoint, which is stored in Bedrock's own binary codec
- The opaque `Block` and `LeeTransaction` payloads of the sequencer RPC
- Gossip messages between sequencers (transactions and channel-config approvals)
- Instruction data, the built-in programs' shard contents, event data, and L1 deposit metadata

Borsh uses little-endian integers, and lists and maps carry a `u32` little-endian length prefix.

### JSON-RPC encoding

Both services accept JSON-RPC over HTTP and WebSocket connections on the same port; only the indexer offers subscriptions. The two services (sequencer and indexer) have different JSON representations because they use different type definitions.

In both, tuples are JSON arrays (the sequencer's `getTransaction` returns `[<Base64 transaction>, <block id>]`), an absent `Option` is `null`, `()` is `null`, and integers not listed below are decimal.

All Base64 uses the standard alphabet with padding (`+`, `/`, `=`).

### Sequencer JSON

`Block` and `LeeTransaction` are **opaque** `Base64(Borsh(...))` strings. The entire object is Borsh-encoded then standard Base64-encoded into a single JSON string. There is no field-level JSON structure for these types.

For the remaining sequencer endpoints, the sequencer uses its native Rust types, with their serde encodings:

| Type | JSON encoding |
| --- | --- |
| `AccountId` | Base58 string |
| `HashType` | Lowercase hex string |
| `ChannelId` | Lowercase hex string |
| `Nonce` (u128) | Decimal integer |
| `Balance` (u128) | Decimal integer |
| `ProgramId` (`[u32; 8]`) | JSON array of 8 decimal u32 values, e.g. `[0,0,0,0,0,0,0,1]` |
| `Account` | `{"nonce": <int>, "data": {"shards": {<base58 program AccountId>: <byte array>}}}` |
| Shard data (`ShardData`) | JSON array of byte integers, e.g. `[72,101,108,108,111]` |
| `ProgramShardSelector` | `{"account_id": <base58>, "program_account_id": <base58>}` |
| `Commitment`, `CommitmentSetDigest` (`[u8; 32]`) | JSON array of 32 byte integers |
| `MembershipProof` (`(usize, List<[u8; 32]>)`) | `[<index>, [<32-byte array>, ...]]` |

### Indexer JSON

The indexer defines its own protocol types with explicit per-field encodings:

| Type | JSON encoding |
| --- | --- |
| `HashType` (`[u8; 32]`) | Lowercase hex string |
| `AccountId` (`[u8; 32]`) | Base58 string |
| `Signature` (`[u8; 64]`) | Lowercase hex string |
| `PublicKey` (`[u8; 32]`) | Base64 string |
| `Proof` (`List<u8>`) | Base64 string |
| `Commitment` (`[u8; 32]`) | Base64 string |
| `Nullifier` (`[u8; 32]`) | Base64 string |
| `CommitmentSetDigest` (`[u8; 32]`) | Base64 string |
| `EphemeralPublicKey` (`List<u8>`) | Base64 string |
| `Ciphertext` (`List<u8>`) | Base64 string |
| `Account` | `{"nonce": <int>, "data": {"shards": {<base58 program AccountId>: <Base64 shard bytes>}}}` |
| Shard data (`ShardData`) | Base64 string |
| `instruction_data` (`List<u8>`) | JSON array of byte integers |
| Effect `data` (`EffectData`, `List<u8>`) | JSON array of byte integers |
| `ViewTag` (`u8`) | Decimal integer |
| Event `Selector` (`[u8; 8]`) | Lowercase hex string |
| Event `data` (`List<u8>`) | Base64 string |
| `BlockId`, `Timestamp` (u64) | Decimal integer |
| `Nonce`, `Balance` (u128) | Decimal integer |
| `BedrockStatus` | String enum: `"Pending"`, `"Safe"`, `"Finalized"` |
| `Block`, `Transaction` | Expanded JSON object (fields individually encoded; see below) |

Enums are externally tagged: a transaction is `{"Public": {...}}` or `{"PrivacyPreserving": {...}}`, and a unit variant such as a `BedrockStatus` is its name as a string.

The indexer's `Transaction` does not mirror the LEE layout exactly: each transaction carries its `hash`, the witness set's `proof` is optional (`null` for public transactions), and a privacy-preserving message omits `program_image_claims`. Both validity windows are encoded as `[from, to]` pairs of optional `u64` bounds (`null` for unbounded).

### Configuration files

Sequencer and indexer configuration files are JSON. Durations are written as human-readable strings (e.g. `"10s"`), and sizes as byte-size strings (e.g. `"1 MiB"`).

Settings every node on a channel must agree on:

| Setting | Where | Notes |
| --- | --- | --- |
| `channel_id` | sequencer (`bedrock_config`), indexer | The zone's Bedrock channel. |
| `cross_zone` (presence and peers) | sequencer, indexer | Presence selects the genesis program set and cannot change on an existing chain; a zone that only sends messages declares `"cross_zone": {}`. The peer list must match between the sequencer and the indexer, and changing it needs a restart of both. |
| `channel_params` | sequencer (`bedrock_config`) | `ChannelParams` (see [docs/builtin_programs.md](docs/builtin_programs.md), Sequencer Stake program): `minimum_sequencer_stake`, `posting_timeframe`, `posting_timeout`, `exit_delay`; fixed at genesis. |
| `genesis` | sequencer | `List<GenesisAction>`; used only when creating the channel, after which the genesis block is replayed from Bedrock. |

Everything else is node-local:

- **Sequencer:** `max_block_size`, `max_num_tx_in_block`, `mempool_max_size`, `block_create_timeout` (must be shorter than `posting_timeout`), the signing key, `gossip`, and Bedrock connection settings.
- **Indexer:** `consensus_info_polling_interval`, `event_filter`, `allow_chain_reset`, `cross_zone_accept_unverified`, and `peer_block_cache_window`.

## Transaction Types

The transaction types below are defined by LEE. Their exact layouts and signing rules are reproduced here for clarity.

### `PublicTransaction`

```rust
struct PublicTransaction {
    message: Message,
    witness_set: WitnessSet,
}

struct Message {
    program_account_id: AccountId,                 // program to invoke
    shard_selectors: List<ProgramShardSelector>,   // (account, shard) pairs the call receives
    nonces: List<Nonce>,                           // u128 each, one per signer
    instruction_data: InstructionData,             // borsh-encoded instruction
    fee: Option<FeeDeclaration>,                   // None only for fee-exempt shapes
}

struct WitnessSet {
    signatures_and_public_keys: List<(Signature, PublicKey)>,   // Signature: [u8; 64], PublicKey: [u8; 32]
}

struct FeeDeclaration {
    payer: AccountId,   // must sign the transaction
    gas_limit: Gas,
    tip: Fee,
    max_fee: Balance,
}
```

### `PrivacyPreservingTransaction`

```rust
struct PrivacyPreservingTransaction {
    message: Message,
    witness_set: WitnessSet,
}

struct Message {
    public_actions: List<PublicActionWithID>,
    nonces: List<Nonce>,
    private_actions: List<PrivateAction>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    program_image_claims: List<ProgramImageClaim>,
}

struct PublicActionWithID {
    account_id: AccountId,
    effects: List<DeferredPublicEffect>,
}

struct PrivateAction {
    nullifier: Nullifier,
    root: CommitmentSetDigest,
    commitment: Commitment,
    encrypted_post_state: EncryptedAccountData,
}

struct WitnessSet {
    signatures_and_public_keys: List<(Signature, PublicKey)>,
    proof: Proof,   // ZK proof bytes
}
```

The message carries no public post-states: the sequencer applies each public account's deferred effects to live state when it settles the transaction.

### Program deployment

Programs are deployed with ordinary `PublicTransaction`s to the LEE program loader (`WriteSegment`, `CreateHeader`, `UpdateHeader`), which store the bytecode in public accounts. Deployment is therefore signed, nonced, and charged like any other user action.

### `LeeTransaction` (envelope)

```rust
enum LeeTransaction {
    Public(PublicTransaction),
    PrivacyPreserving(PrivacyPreservingTransaction),
}
```

A transaction's hash, as returned by `sendTransaction` and used by `getTransaction`, gossip, and the indexer, is `SHA256(borsh(tx))` of the inner `PublicTransaction` or `PrivacyPreservingTransaction`, witness set included. It differs from LEE's message hash, which covers only the message.

## Cryptography

### Block signing

```rust
/// ASCII "/LEE/v0.3/Message/Block/" zero-padded to 32 bytes
const BLOCK_PREFIX: [u8; 32] = *b"/LEE/v0.3/Message/Block/\x00\x00\x00\x00\x00\x00\x00\x00";

struct HashableBlockData {
    block_id: BlockId,
    prev_block_hash: BlockHash,
    timestamp: Timestamp,         // milliseconds since Unix epoch
    transactions: List<LeeTransaction>,
}

fn block_hash(data: &HashableBlockData, producer: &PublicKey) -> BlockHash {
    // borsh(producer) is the raw 32-byte x-only public key
    sha256(BLOCK_PREFIX || borsh(data) || borsh(producer))
}
```

The producing sequencer signs `block_hash` using its **BIP340 Schnorr key** (secp256k1). Its public key is stored in `BlockHeader.producer` and is covered by the hash; the resulting 64-byte signature is stored in `BlockHeader.signature`. As with LEE transaction signatures (see [`lee-specs.md`](lee-specs.md#witness-set)), the signed message is the 32-byte hash itself, not hashed again, and signing uses random auxiliary data, so signatures are not deterministic. A block is valid only if the signature verifies against `producer` *and* `header.hash` equals the hash recomputed from the block contents.

### Sequencer keys

A sequencer holds four keys:

| Key | Scheme | Used for |
| --- | --- | --- |
| Block-signing key | BIP-340 (secp256k1) | Signing blocks. Peer zones pin it (`expected_block_signing_pubkeys`). |
| Bedrock key (`SequencerKey`) | Ed25519 | Accreditation on the channel, inscriptions, channel-config approvals, and slash approvals. |
| Stake ownership key | BIP-340 (a LEE account key) | Owns the ownership account, which is also the reward account; signs `Stake` and `UnstakeRequest`. |
| Bedrock funding key | Bedrock zk key (`ZkPublicKey`) | Pays the fees of the sequencer's Bedrock transactions. |

### Slash approvals

A `Slash` is authorized by Ed25519 signatures from the committee's Bedrock keys. Each approver signs:

```rust
fn slash_approval_message(channel_id: ChannelId, offender: SequencerKey, inscription: [u8; 32]) -> List<u8> {
    SLASH_APPROVAL_DOMAIN || channel_id || offender || inscription   // 128 bytes
}
```

The channel id keeps an approval to one zone, and the inscription keeps it single-use. A `Slash` needs approvals from `max(2, ⌈2n/3⌉)` distinct accredited members, where `n` is the number of accredited members; each signature is verified strictly.

### Genesis stake signatures

A `StakeSequencer` genesis action's `stake_signature` is the owner's BIP-340 signature over the message hash of that founding sequencer's genesis `Stake` transaction. The genesis funding account adds the transaction's other signature.

## Block Structure

```rust
struct Block {
    header: BlockHeader,
    body: BlockBody,
    bedrock_status: BedrockStatus,
}

struct BlockHeader {
    block_id: BlockId,            // sequential from 1
    prev_block_hash: BlockHash,
    hash: BlockHash,              // see Block signing
    timestamp: Timestamp,         // milliseconds since Unix epoch
    producer: PublicKey,          // producer's BIP340 public key
    signature: Signature,         // producer's BIP340 signature over `hash`
}

struct BlockBody {
    transactions: List<LeeTransaction>,
}

enum BedrockStatus { Pending, Safe, Finalized }
```

`bedrock_status` is not covered by the block hash or signature. It is published as `Pending` and set locally by each reader: the sequencer promotes a block to `Finalized` when its inscription is finalized, and the indexer marks every block it reads as `Finalized`.

A block is published as its Borsh encoding, which must fit the sequencer's `max_block_size` (default 1 MiB). The sequencer refuses to start if `max_block_size` exceeds Bedrock's inscription size limit (`MAX_PUBLISHABLE_BLOCK_SIZE`, Bedrock's `inscribe::MAX_BYTES`). The body always ends with the fee invocation followed by the clock invocation (see Block acceptance criteria).

The stored `BlockMeta` record is `{ id: BlockId, hash: BlockHash }`.

### Block acceptance criteria

A block is valid on top of the current tip if all of the following hold. The sequencer and the indexer apply the same rules (`chain_state::apply_block`).

- **Integrity:** `header.hash` equals the recomputed block hash, and `signature` verifies against `producer`.
- **Chaining:** `block_id` is the tip's `block_id + 1`, and `prev_block_hash` is the tip's hash. The first block must have `block_id` 1; its `prev_block_hash` is not checked.
- **Shape:** The block has at least two transactions, and the last two are public.
- **Clock tail:** The **last** transaction is exactly `clock_invocation(block_id, timestamp)`.
- **Fee tail:** The **second-to-last** transaction is exactly the fee invocation for this block: the fee summary derived from settling the block's user transactions, the resulting payout, and a producer reward account that is not a restricted system account (see Fees).
- **User transactions:** Every other transaction applies, meaning it meets LEE's acceptance criteria (see [`lee-specs.md`](lee-specs.md#public-transaction-acceptance-criteria)). In the genesis block these must be public transactions, applied directly; in every other block each one settles through the fee rules (see Fees).
- **Restricted accounts:** Outside the genesis block, no user transaction modifies a system account in a way only system transactions may (see System accounts).
- **Gas caps:** The block's total charged execution and storage gas stay within `MAX_GAS_EXEC` and `MAX_GAS_STOR`.

**Charging.** A charged transaction whose *action* reverts still counts as applied: it pays its fee and burns its signers' nonces. A charged transaction that fails its fee preconditions (static checks, payer signature, reserve) or that LEE rejects (signature or nonce failure, malformed input, unknown top-level program), or an exempt transaction that fails, makes the block invalid.

In pseudocode:

```rust
/// The block a new block must extend.
struct Tip {
    block_id: BlockId,
    hash: BlockHash,
}

fn apply_block(tip: Option<Tip>, block: Block, state: &mut V03State) {
    // Integrity and chaining
    assert_eq!(block.recompute_hash(), block.header.hash);
    assert!(block.header.signature.is_valid_for(block.header.hash, block.header.producer));
    match tip {
        None => assert_eq!(block.header.block_id, GENESIS_BLOCK_ID),
        Some(tip) => {
            assert_eq!(block.header.block_id, tip.block_id + 1);
            assert_eq!(block.header.prev_block_hash, tip.hash);
        }
    }

    // Forced tail
    let [user_txs @ .., fee_tx, clock_tx] = block.body.transactions;
    assert_eq!(clock_tx, clock_invocation(block.header.block_id, block.header.timestamp));

    // User transactions settle against the fee state the block opened on
    let opening = fee_state(state);
    let mut summary = BlockFeeSummary::default();
    for tx in user_txs {
        if block.header.block_id == GENESIS_BLOCK_ID {
            state.transition_from_public_transaction(tx);   // exempt, public only
        } else {
            settle_transaction(tx, state, opening, &mut summary);   // see Fees
        }
    }

    // The fee tail must carry exactly this block's summary and payout
    let producer = fee_invocation_producer(fee_tx);
    assert_eq!(fee_tx, fee_invocation(summary, block_payout(opening, summary), producer));
    assert!(!is_restricted_system_account(producer));
    state.transition_from_public_transaction(fee_tx);
    state.transition_from_public_transaction(clock_tx);
}
```

These rules do not check a system injection against its source: a bridge `Deposit` or inbox `Dispatch` forged in the injection shape still applies. The indexer's cross-zone check covers dispatches (see Indexer Flow); deposits are not yet verified against their L1 event.

The block timestamp is not validated: it need not increase, and it is not bounded by the current time. The clock program checks only that `block_id` advances by one, so the timestamp in the clock accounts, and the one LEE checks timestamp validity windows against, is whatever the producer chose.

### Note on replay attacks

Signed transactions are protected by LEE's nonces. Fee-exempt system transactions carry no signature and no nonce, so LEE leaves their admission to LEZ (see [`lee-specs.md`](lee-specs.md#note-on-replay-attacks)). Each is protected by its own mechanism:

| Transaction | Replay protection |
| --- | --- |
| Clock invocation | Positional: only the last transaction of a block, built from the header; the clock program also requires `block_id` to advance by one. |
| Fee invocation | Positional: only the second-to-last transaction of a block, byte-compared against the block's own summary. The Fee program is sequencer-only. |
| Bridge `Deposit` | The deposit-receipt PDA: a nonempty receipt refuses a repeat of the same op id. The sequencer also drops user- and gossip-submitted deposits. |
| Inbox `Dispatch` | The seen shard: each `(src_zone, src_block_id)` records its delivered `src_tx_index`es and refuses a repeat. |
| `ping_sender` `Send` | The outbox slot is write-once, so a repeat fails. |

A replayed exempt transaction fails, and a failed exempt transaction makes the block invalid.

## Fees

LEZ charges fees on user public transactions. The fee market has two dimensions, execution gas (zkVM cycles) and storage gas (serialized bytes), each with its own base fee that adjusts per block toward a target.

### Which transactions pay

| Transaction | Fee treatment |
| --- | --- |
| User public transaction | **Charged**. Must carry a `FeeDeclaration`; omitting it makes the block invalid. |
| Privacy-preserving transaction | Exempt (interim policy). |
| System injections (empty witness set): bridge `Deposit`, cross-zone inbox `Dispatch`, `ping_sender` `Send` | Exempt. |
| Cross-zone outbound lock (`bridge_lock::Lock`) | Exempt. |
| Sequencer Stake program invocations (stake, unstake request, finalize unstake, slash, channel params) | Exempt. |
| Genesis transactions, the fee invocation, the clock invocation | Exempt. |

### Settling a charged transaction

Each charged transaction settles against the fee state the block *opened* on:

1. **Static checks.** `data_bytes` (the transaction's serialized size) is in `1..=MAX_GAS_STOR`, `gas_limit ≤ MAX_GAS_EXEC`, and the reserve does not exceed `max_fee`. The payer must have signed the transaction. A transaction that fails these checks makes the block invalid.
2. **Reserve.** `gas_limit·base_fee_exec + data_bytes·base_fee_stor + tip` is moved from the payer to the fee inbox. A payer who cannot fund it makes the block invalid.
3. **Action.** The transaction executes with a cycle budget of `gas_limit`. If LEE rejects it (a signature or nonce failure, malformed input, or an unknown top-level program), the block is invalid. Any other failure reverts it: its effects are dropped, but the fee stays and the signers' nonces advance.
4. **Refund.** The unspent part of the reserve (priced at the executed cycles, clamped to `gas_limit`) is returned from the inbox to the payer.

The reserve and refund are LEE fee-settlement invocations (see [`lee-specs.md`](lee-specs.md#fees)): they advance no nonces. The reserve authorizes only the payer; the refund authorizes no account and is skipped when nothing is left to return. Neither is metered: `gas_used_exec` and the `MAX_GAS_EXEC` cap count only the action's cycles, and the fee and clock tail are unmetered too.

```rust
fn fee_reserve(tx: &FeeDeclaration, data_bytes: Gas, fees: &FeeState) -> Balance {
    tx.gas_limit * fees.base_fee_exec + data_bytes * fees.base_fee_stor + tx.tip
}

fn fee_base(charged_cycles: Cycles, tx: &FeeDeclaration, data_bytes: Gas, fees: &FeeState) -> Balance {
    min(charged_cycles, tx.gas_limit) * fees.base_fee_exec + data_bytes * fees.base_fee_stor
}

// refund = fee_reserve - (fee_base + tip)
```

The block accumulates `gas_used_exec` (charged cycles, clamped to `gas_limit`), `gas_used_stor` (`data_bytes`), and base and tip revenue into a `BlockFeeSummary`:

```rust
struct BlockFeeSummary {
    gas_used_exec: Gas,
    gas_used_stor: Gas,
    revenue_base: Balance,   // Σ fee_base
    revenue_tip: Balance,    // Σ tip
}
```

A block whose `gas_used_exec` or `gas_used_stor` exceeds `MAX_GAS_EXEC` or `MAX_GAS_STOR` is invalid.

### Block-tail distribution

The fee program's `Distribute` instruction, the forced second-to-last transaction, applies the block's summary to the fee state: it updates both base fees, moves base revenue from the inbox into escrow, pays tips to the producer, and pays the producer a payout smoothed over the last `SMOOTHING_WINDOW` (50) blocks from escrow. The producer chooses its reward account (a sequencer uses its stake ownership account); it may not be a clock, fee, or bridge account.

The fee state is stored in the fee state account (Borsh, 840 bytes):

```rust
struct FeeState {
    base_fee_exec: Fee,                   // execution base fee for the current block
    base_fee_stor: Fee,                   // storage base fee for the current block
    window: [u128; SMOOTHING_WINDOW],     // base revenue of the last SMOOTHING_WINDOW blocks
    payout_carry: u128,                   // payout division remainder, always < SMOOTHING_WINDOW
    height: u64,
}
```

At genesis both base fees are at their minimum and every other field is zero. The escrow is the escrow account's native balance, not a field.

Applying a block's summary:

1. `height` increments, and `window[height % SMOOTHING_WINDOW]` is set to the block's `revenue_base`.
2. The payout is `(payout_carry + Σ window) / SMOOTHING_WINDOW`, and the remainder becomes the new `payout_carry`.
3. Each base fee moves toward its target:

```rust
/// `lo` / `hi` are BASE_FEE_*_MIN / BASE_FEE_*_MAX, and `d` is D_EXEC / D_STOR.
fn next_base_fee(base_fee: Fee, gas_used: Gas, target: Gas, d: u64, lo: Fee, hi: Fee) -> Fee {
    if gas_used > target {
        let delta = max(1, base_fee * min(gas_used - target, target) / (target * d));
        min(base_fee + delta, hi)
    } else if gas_used < target {
        let delta = base_fee * min(target - gas_used, target) / (target * d);
        max(base_fee - delta, lo)
    } else {
        base_fee
    }
}
```

With `MAX_GAS = 2·TARGET` and `D = 8`, a base fee moves by at most 12.5% per block, and by at least 1 upward whenever usage is above target.

| Constant | Value |
| --- | --- |
| `TARGET_GAS_EXEC` / `MAX_GAS_EXEC` | 5,000,000 / 10,000,000 cycles |
| `TARGET_GAS_STOR` / `MAX_GAS_STOR` | 500,000 / 1,000,000 bytes |
| `D_EXEC`, `D_STOR` | 8 |
| `BASE_FEE_EXEC_MIN`, `BASE_FEE_STOR_MIN` | 8 |
| `BASE_FEE_EXEC_MAX` / `BASE_FEE_STOR_MAX` | `u64::MAX / MAX_GAS_EXEC` (1,844,674,407,370) / `u64::MAX / MAX_GAS_STOR` (18,446,744,073,709) |
| `SMOOTHING_WINDOW` | 50 blocks |

Changing any of these constants is a protocol-version change.

## System Programs

See [docs/builtin_programs.md](docs/builtin_programs.md). LEZ comes with a fixed set of built-in programs. They are pre-compiled into the node binary and registered in the initial state at startup, each at a name-derived address, `from_builtin_program_name(name)`, that stays fixed across code changes. They are seeded as immutable.

The LEE native token program (native balances) and the LEE program loader (deployment) are not listed: they are part of LEE and implemented in protocol code rather than as guest programs.

| Program | Name | Role |
| --- | --- | --- |
| **Clock** | `clock` | Writes the current block ID and timestamp into three dedicated system accounts on every block. Only the sequencer may invoke it (as the mandatory last transaction). |
| **Fee** | `fee` | Runs the per-block fee distribution and per-transaction refunds. Sequencer-only: user transactions invoking it are rejected. |
| **Bridge** | `bridge` | `Deposit` transfers native tokens from the system bridge account to a recipient, exactly once per L1 deposit op id. `Withdraw` is defined but disabled: the program refuses it (see Bridge withdrawals). |
| **Sequencer Stake** | `sequencer_stake` | Tracks sequencer stakes and the channel's posting parameters: `Stake`, `UnstakeRequest`, `FinalizeUnstake`, `InitChannelParams`, `Slash`. |

Zones configured with `cross_zone` additionally register six cross-zone programs: `cross_zone_inbox`, `cross_zone_outbox`, `ping_sender`, `ping_receiver`, `bridge_lock`, and `wrapped_token` (see Cross-zone messaging).

### System accounts

Several categories of accounts exist outside normal user control. The table lists the accounts protected by the restricted-account guard: the sequencer and every follower reject user transactions that modify them in ways only system transactions may. Other program-owned accounts, such as stake funds PDAs, the slashed stake sink, and the cross-zone escrow and holding PDAs, are protected by their owning program's own rules instead.

| Account | Derivation | Purpose | User transactions may |
| --- | --- | --- | --- |
| **Bridge** | PDA of the Bridge program | Holds the whole unissued supply (`u128::MAX` at genesis). Genesis allocations and L1 deposits are both `Deposit`s that draw on it. | Only increase its native balance (e.g. a native transfer into it); privacy-preserving transactions may not touch it. |
| **Fee state / escrow / inbox** | PDAs of the Fee program | Fee market state, payout escrow, and per-block collection point. | Never modify. |
| **Clock (×3)** | Fixed IDs: `CLOCK_01`, `CLOCK_10`, `CLOCK_50` | Store `(block_id, timestamp)`. Updated every 1, 10, and 50 blocks respectively. Programs read these accounts to access the current block time. | Never modify. |
| **Sequencer stake config** | PDA of the Sequencer Stake program | Channel parameters and the stake entries. | Only through the Sequencer Stake program's rules. |

Any account's cross-zone inbox shard may be written only by an inbox `Dispatch`.

### Native supply

Native tokens enter LEZ from L1 through bridge deposits, but a deposit does not create them: the bridge account is pre-allocated `u128::MAX` at genesis, and each `Deposit` moves `amount` out of it to the recipient (genesis allocations are `Deposit`s too). The total native balance on LEZ therefore never changes; the bridge's remaining balance is the unissued supply, and everything outside it (apart from the balances the testnet base state pre-funds directly) was issued by a deposit. Withdrawals, which would return tokens to the bridge, are disabled.

Fees move from payers into the fee inbox, then to escrow (base revenue) and the producer (tips and payouts). Slashed stakes are moved into the slashed stake sink PDA, which nothing moves balance out of, so they are burned in effect while still counted in the total.

## Genesis

Genesis runs when a sequencer starts with an empty store. It first asks Bedrock whether the zone's channel exists.

- **Creating the channel.** If the channel does not exist, the sequencer builds the genesis block below and publishes it. With founding stakes configured, the genesis block is published together with the channel creation, which lists the founding committee's Bedrock keys (the creator's first, then the others sorted) and hands the first turn to the creator. With none configured, the creator stakes itself, and genesis is published as an ordinary inscription on a channel that accredits only the creator.
- **Joining an existing channel.** If the channel exists, the sequencer builds a placeholder genesis locally, without a self-stake, and replaces it with the channel's real blocks during reconstruction. It never publishes its own genesis.

### State initialisation

`V03State` is built in two phases:

1. **Base state** — all built-in programs are registered (plus the cross-zone set when `cross_zone` is configured). The three clock accounts are seeded with `(block_id: 0, timestamp: 0)`. The bridge account (balance `u128::MAX`), the fee state account (genesis market state), the empty fee escrow and inbox accounts, and an empty sequencer stake config account are created. The testnet base state also funds a few fixed test accounts, public and private.
2. **Genesis transactions** — everything else is applied as transactions, so any follower can reproduce the state by replaying the genesis block:
    - `InitChannelParams` sets the channel's posting parameters and channel id in the sequencer stake config.
    - On cross-zone zones, the cross-zone programs' `InitConfig` transactions.
    - The sequencer config `genesis` field (`List<GenesisAction>`):
        - `SupplyAccount { account_id, balance }` — a bridge `Deposit` crediting `balance` from the bridge account directly to `account_id`.
        - `SupplyBridgeLockHolding { holder, amount }` — a bridge `Deposit` into the holder's `bridge_lock` holding PDA (cross-zone zones only).
        - `StakeSequencer { sequencer_key, ownership_public_key, stake_signature }` — a founding committee member, staked with exactly `minimum_sequencer_stake`. Each is funded by a genesis `Deposit` into a fixed genesis funding account (the public account of the well-known private key `[9u8; 32]`, empty once genesis has run) and then staked with a `Stake` transaction signed by both that account and the owner. If no `StakeSequencer` is configured, the channel-creating sequencer stakes itself.

    The supply `Deposit`s come first, in config order, then one funding `Deposit` per founding stake, then the `Stake` transactions.

    Each genesis `Deposit` carries a synthetic op id, `b"/LEZ/v0.3/GenesisDeposit" || index_u64_le`, where `index` is the action's position in the genesis list (counting an appended self-stake; a funding `Deposit` uses its stake action's index). No L1 op id can collide with it, and its receipt PDA stops a later block from replaying it.

```rust
enum GenesisAction {
    SupplyAccount { account_id: AccountId, balance: u64 },
    /// Cross-zone zones only.
    SupplyBridgeLockHolding { holder: AccountId, amount: u64 },
    StakeSequencer {
        sequencer_key: SequencerKey,
        ownership_public_key: PublicKey,
        stake_signature: Signature,
    },
}
```

### Genesis block assembly

After the genesis transactions, the mandatory fee invocation (with an empty summary, crediting the first founding sequencer's ownership account) and clock transaction (`clock_invocation(1, 0)`) are appended. The genesis block is then assembled:

```rust
HashableBlockData {
    block_id: GENESIS_BLOCK_ID,   // 1
    prev_block_hash: [0u8; 32],
    timestamp: 0,
    transactions: [
        init_channel_params,
        /* cross-zone configs... */
        /* genesis actions... */
        fee_invocation,
        clock_invocation(1, 0),
    ],
}
```

The block is signed with the sequencer's block-signing key. The channel creator publishes it as described above, so the indexer can locate the channel start.

On a restart the sequencer loads its stored chain instead of rebuilding genesis. It then checks that the store still belongs to the chain the channel serves, and replays any finalized blocks it is missing. If the channel proves a different chain, it refuses to start.

The genesis program set depends on whether `cross_zone` is configured; it must match the indexer's and cannot change on an existing chain.

## Clock Transaction

Every block contains a mandatory clock transaction appended as the **last transaction**, immediately after the fee invocation:

```rust
const CLOCK_01_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000001");
const CLOCK_10_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000010");
const CLOCK_50_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000050");
const CLOCK_PROGRAM_ACCOUNT_IDS: [AccountId; 3] = [
    CLOCK_01_PROGRAM_ACCOUNT_ID,
    CLOCK_10_PROGRAM_ACCOUNT_ID,
    CLOCK_50_PROGRAM_ACCOUNT_ID,
];

fn clock_invocation(block_id: BlockId, timestamp: Timestamp) -> PublicTransaction {
    PublicTransaction {
        message: Message {
            program_account_id: clock_account_id(),          // from_builtin_program_name(b"clock")
            shard_selectors: CLOCK_PROGRAM_ACCOUNT_IDS,      // each with the clock program's shard
            nonces: [],                                      // empty
            instruction_data: borsh(Instruction { timestamp, block_id }),
            fee: None,
        },
        witness_set: WitnessSet {
            signatures_and_public_keys: [],                  // empty
        },
    }
}
```

The clock transaction provides the block timestamp to all other transactions via the LEE state machine. It has no signature and no nonce. It is built from the block header's `block_id` and `timestamp`, so followers reconstruct exactly the same transaction, and the clock program checks that `block_id` advances its stored ID by one.

## Sequencer Flow

### Transaction submission

Users submit transactions via `sendTransaction`. The sequencer performs **stateless validation**:

1. Transaction size — Borsh-encoded size must not exceed `max_block_size - BLOCK_OVERHEAD` (2,048 bytes reserved for the header and the forced fee and clock transactions)
2. No duplicate signers in the witness set
3. Signature validity — all signatures must verify against the message hash
4. The transaction does not invoke a sequencer-only program (the cross-zone inbox or the fee program) at the top level

For a privacy-preserving transaction only the signatures are checked here; its proof is verified when the transaction settles in a block.

It then **screens the fee** against the head state: a charged transaction must pass the static fee checks, carry the payer's signature, and the payer must currently hold the reserve.

Failures return JSON-RPC error `-32602` (InvalidParams) with a description. Valid transactions are added to the mempool; if gossip is enabled, they are then published to peer sequencers.

### Mempool

- In-memory bounded queue with configurable max size (`mempool_max_size`); its contents do not survive a restart
- When the queue is full, submission fails immediately with error `-31900` ("Mempool is full")
- Entries are tagged `User` (submitted over RPC, or returned from an orphaned block) or `Gossip` (received from a peer sequencer)
- The queue is FIFO, except that deferred transactions, and the transactions of a block discarded because the channel moved, are re-queued at the front in their original order
- Transactions are not deduplicated; a repeated transaction fails settlement on its nonce and is dropped
- Bridge deposits, cross-zone deliveries, slashes, and unstake finalizations never enter the mempool: they are drained from the store or built fresh each turn, ahead of mempool transactions, and tagged `Sequencer`

### Block production

A sequencer produces a block only when Bedrock reports that it holds the channel's posting turn, and only if its Bedrock key has a stake entry (the entry's ownership account is its reward account). On every `block_create_timeout` interval while it holds the turn:

1. Build on the current head: its tip is the parent, its state the validation base
2. Drain pending bridge deposits and cross-zone deliveries (at most `MAX_DISPATCHES_PER_BLOCK`) from the store (skipping any already applied), then any `Slash` transactions the slasher proposes, and `FinalizeUnstake` transactions whose exit delay has passed
3. Pop transactions from the mempool (FIFO order, except previously deferred transactions are re-inserted at the front)
4. Apply each transaction to the working state, stopping at `max_num_tx_in_block` transactions (store-drained ones included):
    - A store-drained transaction is exempt and applied directly. If it fails it is skipped and drained again next turn; a failed delivery also counts toward its retirement.
    - A mempool transaction is dropped if it is a bridge `Deposit`, then screened for its fee, then settled on a scratch copy of the state exactly as a follower would (see Block acceptance criteria and Fees). One that fails is **silently dropped** (error logged; no error sent to submitter).

    A transaction that would push the block over `max_block_size`, or its declared gas over the block caps, is deferred to the next block, and the block takes no further transactions. A store-drained transaction too large for even an empty block, or any transaction whose declared gas exceeds the caps outright, is dropped instead.
5. Append the fee invocation (with the derived summary and payout, crediting this sequencer's stake ownership account) and the mandatory clock transaction
6. Compute block hash and sign with the sequencer's block-signing key
7. Publish block to Bedrock (Borsh-serialized bytes via zone-sdk), pinned to its parent and bundling any bridge withdrawals the block contains (none while `Withdraw` is disabled). If the channel moved while the block was being built, the block is discarded and its mempool transactions are re-queued at the front
8. Record the block and advance the head

Blocks are produced on every turn tick even if the mempool is empty (fee-and-clock-only block).

The block timestamp is the sequencer's wall clock (milliseconds) at the time it builds the block.

After publishing, the turn holder also submits any pending channel-config update (see Sequencer committee) as a separate Bedrock transaction; a draft still unsigned from an earlier turn is discarded first.

A failed turn costs only that block: the sequencer tries again on its next tick. If the channel moved while it was building, it skips the turn to catch up.

`block_create_timeout` must be shorter than the channel's `posting_timeout`, or a healthy sequencer loses its turn between its own blocks.

### Finality

Each sequencer keeps a two-tier chain state: an irreversible **final** tier, advanced by blocks whose inscriptions Bedrock has finalized, and a **head** derived by applying the channel's unfinalized blocks on top of it. Production always builds on the head.

Each Bedrock channel update is applied in order: finalized entries first, then the view change.

- *for Finalized Inscription Operations*, the sequencer advances the final tier, marks the corresponding stored L2 blocks as `Finalized`, and removes the records of deposits and cross-zone deliveries those blocks settled. A finalized block that does not apply leaves the final tier where it was,
- *for every finalized update*, the sequencer's slasher checks the newly finalized entries for slashable offences (see Slashing under Sequencer committee),
- *for Finalized Deposit Operations*, the sequencer records the deposit for inclusion (see Bridge deposits),
- *for Finalized Withdraw Operations*, the sequencer reconciles them against the withdrawals it published,
- *for the view change*, the sequencer either extends the head with peer blocks it adopts, stored as `Pending`, or, on a conflict, replaces the head with the canonical lineage,
- *for orphaned blocks* (blocks that left the head without finalizing), the sequencer returns their transactions, other than the clock and fee invocations, bridge deposits, and cross-zone dispatches, to the back of the mempool (dropping them if it is full) so a later turn re-includes them.

Each update is persisted atomically with the zone-sdk checkpoint and a snapshot of the final tier, so a restart resumes where it left off; offences are reported before that write. Re-delivered deposits and finalizations are idempotent. When the head moves, the sequencer refreshes its view of the accredited and staked keys.

See Block Structure for how `bedrock_status` follows finality.

### Bridge deposits

When Bedrock delivers a finalized deposit (`FinalizedOp::Deposit`), the sequencer:

1. Persists the pending deposit record (op id, source tx hash, amount, metadata) so it survives a crash before inclusion. Deposits reach a block only this way: the sequencer drops a bridge `Deposit` submitted by a user or received by gossip
2. On its next production turn, decodes the event's `metadata` to extract the recipient. The metadata must be exactly the Borsh encoding of `{ recipient_id: AccountId }`, that is, the 32-byte ID of the public account to credit; a deposit whose metadata does not decode is skipped with a warning and never minted
3. Constructs a `PublicTransaction`:
    
    ```rust
    PublicTransaction {
        message: Message {
            program_account_id: bridge_account_id(),
            shard_selectors: [
                native_balance(system_bridge_account_id()),
                native_balance(recipient_id),
                (deposit_receipt_pda(l1_deposit_op_id), bridge_account_id()),   // bridge program shard
            ],
            nonces: [],
            instruction_data: borsh(bridge_core::Instruction::Deposit {
                l1_deposit_op_id,
                recipient_id,
                amount,
            }),
            fee: None,
        },
        witness_set: WitnessSet { signatures_and_public_keys: [] },   // empty
    }
    ```
    
4. Includes it in the block, unless the deposit-receipt PDA already marks the op id as minted

The deposit-receipt PDA is what makes a deposit apply exactly once, even if it is delivered twice or its block is orphaned and rebuilt. The deposit credits `recipient_id` directly and emits a `bridge::Deposit` event (see Events). Its pending record is removed once the block containing it finalizes (see Finality).

### Bridge withdrawals

Withdrawals are disabled: the bridge program refuses `Withdraw { amount, bedrock_account_pk }`, so no block contains one. The sequencer's publishing path is kept: for each withdrawal in a block it bundles a matching channel withdraw (a note of `amount` to `bedrock_account_pk`) with the block's publication, and reconciles finalized withdraw events by note id.

### Sequencer committee

- **Staking.** A key belongs to the *staked set* while its `total_staked - total_pending_unstake` is at least `minimum_sequencer_stake`. At genesis the founding committee is staked by the genesis block (see Genesis). Afterwards an operator stakes with `Stake` transactions signed by a funding account and the ownership account (the `submit_stake` tool sends them from a wallet); the node does not stake itself. `UnstakeRequest` starts an exit that `FinalizeUnstake` completes after `exit_delay` blocks; the sequencer submits the finalizations automatically.
- **Accreditation.** Whenever the staked set differs from the keys Bedrock accredits on the channel, or the live threshold differs from the one the committee's size calls for, the turn holder proposes a channel-config update as a funded draft transaction, and peers sign that exact transaction over gossip. The update must carry as many signatures as the live channel's threshold, and sets the new threshold to `max(1, min(⌈2n/3⌉, n - 1))` for its new committee of `n` keys. The `n - 1` cap lets the rest of the committee eject a key without its signature, and a single-signer channel's update lands on the proposer's own signature. A newly staked sequencer can produce once an update has accredited its key.
- **Turns.** Bedrock runs round robin over the accredited keys: a turn lasts `posting_timeframe` slots and passes on after `posting_timeout` idle slots.
- **Slashing.** Each sequencer runs a *slasher* that checks every finalized update for slashable offences: a finalized inscription that is not a block (`NotABlock`), or a finalized block that should have extended the final tip but does not validate (`InvalidBlock`) or does not chain onto it (`MisplacedBlock`). For each offence it signs an approval with its Bedrock key and gossips it (see Slash approvals); once enough approvals are collected, it proposes a `Slash` transaction for its next block. The `Slash` burns the offender's whole stake and removes its entry, after which a config update removes it from the channel.
- **Gossip.** Optional libp2p gossip carries three topics: submitted transactions, slash approvals, and channel-config drafts and signatures. Transaction spreading is a latency optimization that falls back to L1. Without gossip, however, a committee whose config threshold is above one cannot reconfigure, and no sequencer can be slashed.

## Cross-zone messaging

Zones configured with `cross_zone` can exchange messages. On the source zone, an emitter program (`ping_sender`, `bridge_lock`) sends a message through the outbox. Each destination sequencer watches its configured peers' channels, extracts the messages addressed to it from their finalized blocks, and injects a sequencer-only inbox `Dispatch` transaction for each. The destination's indexer re-derives every dispatch from the peer's finalized blocks before applying it, and halts ingestion on a forged one. `bridge_lock` and `wrapped_token` use this channel to move balances between zones, and `ping_sender` / `ping_receiver` are a minimal example pair. The programs themselves are specified in [docs/builtin_programs.md](docs/builtin_programs.md).

- **Peer authentication.** The watcher accepts a peer block only if its hash is intact and it is signed by one of the peer's configured `expected_block_signing_pubkeys`; an empty list skips this check, leaving only the channel-signer authentication zone-sdk provides. If `min_committee_size` is set and the peer's live committee drops below it, the watcher suspends reading that peer until it recovers.
- **Peer chain.** The watcher and the indexer's verifier admit peer blocks through the same policy. Each peer is followed as a hash-linked chain from its genesis: a block is accepted only as the next link on the stored peer tip, blocks off that chain are read past, and a different block at an already-accepted id is reported as equivocation.
- **Configuration.** `cross_zone.peers` lists each peer's `channel_id` (its zone id), `allowed_routes`, `expected_block_signing_pubkeys`, and `min_committee_size`. Routes are not enforced in transit: they are written into each target program's config at genesis, and the target refuses sources it did not authorize. An optional `source_authority` (with `source_governance` for a PDA authority) may later change those sources; it is set only at genesis, cannot be rotated, and its compromise lets the holder authorize any source. Peers are read at startup, so adding one needs a restart of both the sequencer and the indexer, whose peer lists should match.
- **Per-block cap.** A block carries at most `MAX_DISPATCHES_PER_BLOCK` (16) dispatches; the rest wait for the next block.
- **Dead letters.** A delivery that fails `RETIRE_DISPATCH_AFTER_FAILURES` (3) times, or that cannot fit even an empty block, is retired. Up to 256 dead letters are retained, and they can be inspected and requeued over RPC (`getCrossZoneDeadLetters`, `requeueCrossZoneDeadLetter`).
- **Operator override.** The indexer's `cross_zone_accept_unverified` config lists block hashes it applies without cross-zone verification, to clear a forged verdict or a dead peer.

## Indexer Flow

### Block consumption

The indexer reads finalized channel messages from Bedrock through zone-sdk, starting at its stored cursor and waiting `consensus_info_polling_interval` between passes and after errors. For each block inscription:

1. Deserialize the Borsh payload into a `Block`
2. On cross-zone zones, verify every cross-zone dispatch the block carries against the peer's finalized blocks (skipped for a block listed in `cross_zone_accept_unverified`)
3. Validate the block against the indexed tip and apply its transactions to reconstruct LEE state, using the same rules as the sequencer (see Block acceptance criteria); a re-delivered block already applied is skipped
4. Store the block and resulting state, overwriting `bedrock_status` to `Finalized` (every block read from Bedrock is by definition finalized)
5. Advance the cursor once every message of the L1 slot has been handled (one slot can carry several L2 blocks)
6. Notify subscribers

`ZoneMessage::Deposit` and `ZoneMessage::Withdraw` messages are ignored by the indexer.

If the Borsh payload fails to deserialize, or a block does not validate or apply, the indexer **parks**: it records the stall durably, reports it through `getStatus` (`Stalled`), and keeps its indexed tip frozen, while the L1 cursor still advances. A failure that may be transient is retried up to `APPLY_RETRY_LIMIT` (3) times before parking, and a store error is retried from the same cursor. A later block that chains onto the tip resumes ingestion.

A dispatch that fails cross-zone verification instead **halts** the indexer: it persists a `CrossZoneHalt` record, reports `Halted`, and stops ingesting. The record survives restarts and is cleared only when the named block applies, e.g. after the block is listed in `cross_zone_accept_unverified`. A peer that is merely unreachable holds the cursor and is retried.

On startup the indexer checks that its store still belongs to the chain the channel serves, and refuses to start on a mismatch unless `allow_chain_reset` is set.

### Events

Programs emit events from their plans as LEE `ProgramEvent`s (see [`lee-specs.md`](lee-specs.md#execution-model-plan-and-apply)): an 8-byte `selector` and opaque `data`. By convention the selector is the first 8 bytes of `SHA256("<program>::<EventName>")`, and `data` is the Borsh-encoded event.

The indexer records each event of an applied block, excluding those emitted by the fee settlement's reserve and refund, as an `EventRecord`:

```rust
struct EventRecord {
    block_id: BlockId,
    tx_index: u32,
    tx_hash: HashType,
    program_account_id: AccountId,   // the emitting program
    selector: Selector,
    data: List<u8>,
}
```

Which events it persists is set by its `event_filter` config: `archival` keeps every event, and `sources` keeps only those of the listed programs, optionally narrowed to given selectors. The default is an empty `sources` list, which keeps none.

Among the built-in programs only the Bridge emits events:

| Event | Selector | Data |
| --- | --- | --- |
| `bridge::Deposit` | `cd499ae548cdf23d` | `{ l1_deposit_op_id: [u8; 32], recipient_id: AccountId, amount: u64 }` |
| `bridge::Withdraw` | `874b4979947b40e2` | `{ sender_id: AccountId, amount: u64, bedrock_account_pk: [u8; 32] }`; never emitted while `Withdraw` is disabled |

### Subscriptions

The indexer maintains internal pub-sub channels. Each indexed block pushes its `BlockId` to all active block subscribers, and each persisted program event (see Events) is pushed to event subscribers whose filter it matches. A subscriber that cannot accept an event is disconnected; it should re-subscribe and backfill with `getEvents`.

## Domain separator summary

LEE's separators are listed in [`lee-specs.md`](lee-specs.md#domain-separator-summary). Built-in programs live at `from_builtin_program_name(name)`. PDAs are derived with `AccountId::for_public_pda` under the owning program (see [docs/builtin_programs.md](docs/builtin_programs.md)): an unkeyed PDA uses the separator itself as its seed, and a keyed PDA uses `SHA256(separator || keys)`, with the keys listed.

| Purpose | Domain separator |
|---------|-----------------|
| Block hash | `b"/LEE/v0.3/Message/Block/\x00\x00\x00\x00\x00\x00\x00\x00"` |
| Genesis deposit op id (followed by `index_u64_le`) | `b"/LEZ/v0.3/GenesisDeposit"` (24 bytes, unpadded) |
| Clock account (every 1 block) | `b"/LEZ/ClockProgramAccount/0000001"` (the account ID itself) |
| Clock account (every 10 blocks) | `b"/LEZ/ClockProgramAccount/0000010"` (the account ID itself) |
| Clock account (every 50 blocks) | `b"/LEZ/ClockProgramAccount/0000050"` (the account ID itself) |
| Fee state PDA | `b"/LEZ/v0.3/FeeSeed/State/0000000/"` |
| Fee escrow PDA | `b"/LEZ/v0.3/FeeSeed/Escrow/000000/"` |
| Fee inbox PDA | `b"/LEZ/v0.3/FeeSeed/Inbox/0000000/"` |
| Bridge account PDA | `b"/LEZ/v0.3/BridgeSeed/0000000000/"` |
| Bridge deposit receipt PDA (keyed by `l1_deposit_op_id`) | `b"/LEZ/v0.3/BridgeDepositReceipt/0"` |
| Sequencer stake config PDA | `b"/LEZ/v0.3/MinSequencerStake/0000"` |
| Sequencer stake funds PDA | none: the seed is the ownership account's 32-byte ID |
| Slashed stake sink PDA | `b"/LEZ/v0.3/SlashedStakeSink/00000"` |
| Slash approval message | `b"/LEZ/v0.3/SlashApproval/NonBlock"` |
| Cross-zone message key (`SHA256(separator \|\| src_zone \|\| src_block_id_le \|\| src_tx_index_le)`) | `b"/LEZ/v0.3/CrossZoneMsgKey/00000/"` |
| Cross-zone inbox config PDA | `b"/LEZ/v0.3/CrossZoneInboxCfg/000/"` |
| Cross-zone inbox seen shard PDA (keyed by `src_zone`, `src_block_id_le`) | `b"/LEZ/v0.3/CrossZoneInboxSeen/01/"` |
| Cross-zone source marker PDA (keyed by `src_zone`, `src_account_id`) | `b"/LEZ/v0.3/CrossZoneSource/00000/"` |
| Cross-zone outbox slot PDA (keyed by `emitter`, `target_zone`, `ordinal_le`) | `b"/LEZ/v0.3/CrossZoneOutbox/00001/"` |
| Bridge Lock config PDA | `b"/LEZ/v0.3/BridgeLockCfg/0000000/"` |
| Bridge Lock escrow PDA | `b"/LEZ/v0.3/BridgeLockEscrow/0000/"` |
| Bridge Lock holding PDA (keyed by `holder`) | `b"/LEZ/v0.3/BridgeLockHold/000000/"` |
| Wrapped Token config PDA | `b"/LEZ/v0.3/WrappedTokenConfig/00/"` |
| Wrapped Token holding PDA (keyed by `recipient`) | `b"/LEZ/v0.3/WrappedTokenHold/0000/"` |
| Ping Sender config PDA | `b"/LEZ/v0.3/PingSenderCfg/0000000/"` |
| Ping Receiver config PDA | `b"/LEZ/v0.3/PingReceiverCfg/00000/"` |
| Ping record PDA | `b"/LEZ/v0.3/PingRecord/0000000000/"` |

## Sequencer RPC

**Transport**: JSON-RPC (jsonrpsee) over HTTP and WebSocket on the same port, max request body 10 MiB. The sequencer offers no subscriptions.

| Method | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `sendTransaction` | `tx: LeeTransaction` (Base64-Borsh) | `HashType` | Submit a transaction; returns tx hash |
| `getFeeState` | — | `FeeStateQuote` | Current base fees and the band the next block's can move within, for sizing `max_fee` |
| `getBlock` | `block_id: BlockId` | `Block?` | Fetch block by ID |
| `getBlockRange` | `start_block_id: BlockId, end_block_id: BlockId` | `List<Block>` | Fetch an inclusive range of at most `MAX_BLOCK_RANGE_LEN` (1,024) blocks; stops at the first missing block |
| `getLastBlockId` | — | `BlockId` | Head height (may be unfinalized) |
| `getTransaction` | `tx_hash: HashType` | `(LeeTransaction, BlockId)?` | Fetch transaction and its block by hash |
| `getAccount` | `account_id: AccountId` | `Account` | Current account state (all shards) |
| `getAccountView` | `shard_selector: ProgramShardSelector` | `Account` | Account nonce and the one selected shard |
| `getAccountBalance` | `account_id: AccountId` | `Balance` | Account native balance |
| `getAccountsNonces` | `account_ids: List<AccountId>` | `List<Nonce>` | Nonces for multiple accounts |
| `getProofsAndRoot` | `commitments: List<Commitment>` | `(List<MembershipProof?>, CommitmentSetDigest)` | Merkle membership proofs and the current root |
| `getProgramIds` | — | `Map<String, ProgramId>` | Image ID of the privacy-preserving circuit |
| `getChannelId` | — | `ChannelId` | The Bedrock channel this sequencer writes to |
| `getCrossZoneDeadLetters` | — | `CrossZoneDeadLetterReport` | Cross-zone deliveries this sequencer gave up on |
| `requeueCrossZoneDeadLetter` | `message_key: HashType` | `CrossZoneDeadLetterRequeue` | Restore a dead-lettered delivery for another attempt |
| `checkHealth` | — | `()` | Liveness check |

**Error codes:**

| Code | Meaning |
| --- | --- |
| `-32602` | InvalidParams — bad transaction (too large, invalid or duplicate signature, sequencer-only program, fee screen failed, malformed) or a backwards or too-long block range |
| `-32603` | InternalError — database or internal failure |
| `-31900` | Mempool is full |

`getBlock` and `getTransaction` return JSON `null` (an `Option`) for a missing item rather than raising an error.

All queries read the sequencer's head, which includes unfinalized blocks: `getLastBlockId` is the head height, and a returned block may still be `Pending` and later orphaned. `getTransaction` searches only blocks, not the mempool. `getAccount` on an unknown account returns the default account (nonce 0, no shards). For finalized data, use the indexer.

**Result types:**

```rust
struct FeeStateQuote {
    height: u64,                       // block height the quoted state settled at
    base_fee_exec: u64,
    base_fee_stor: u64,
    next_base_fee_exec_floor: u64,     // next block's base fee after an empty block
    next_base_fee_exec_ceiling: u64,   // next block's base fee after a block filled to the caps
    next_base_fee_stor_floor: u64,
    next_base_fee_stor_ceiling: u64,
    max_gas_exec: u64,
    max_gas_stor: u64,
}

struct CrossZoneDeadLetterReport {
    total_retired: u64,                // every give-up, including evicted ones
    retained: List<CrossZoneDeadLetter>,
}

struct CrossZoneDeadLetter {
    message_key: HashType,
    src_zone: ChannelId,
    src_block_id: u64,
    src_tx_index: u32,
    failed_attempts: u32,
    transaction_bytes: u32,
}

/// Serialized in snake_case: "requeued", "already_pending", "not_found", "not_retained".
enum CrossZoneDeadLetterRequeue { Requeued, AlreadyPending, NotFound, NotRetained }
```

Every possible next-block base fee lies within the quote's floor and ceiling. Fee-exempt transactions are not quoted.

The block, transaction, and account queries are slated for removal once the wallet reads from the indexer.

## Indexer RPC

**Transport**: JSON-RPC (jsonrpsee) over HTTP and WebSocket on the same port, max request body 10 MiB. Regular methods work over either; subscriptions require a WebSocket connection (JSON-RPC subscriptions cannot run over plain HTTP).

| Method | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `subscribeToFinalizedBlocks` | — | `Subscription<BlockId>` | Real-time stream of finalized block IDs |
| `subscribeToEvents` | `filter: EventSubscriptionFilter` | `Subscription<EventRecord>` | Real-time stream of program events matching the filter (tx hash, program, selector) |
| `getLastFinalizedBlockId` | — | `BlockId?` | Latest finalized block |
| `getBlockById` | `block_id: BlockId` | `Block?` | Fetch block by ID |
| `getBlockByHash` | `block_hash: HashType` | `Block?` | Fetch block by hash |
| `getBlocks` | `before: BlockId?, limit: u64` | `List<Block>` | Paginated block list |
| `getTransaction` | `tx_hash: HashType` | `Transaction?` | Fetch transaction with block context |
| `getTransactionsByAccount` | `account_id: AccountId, offset: u64, limit: u64` | `List<Transaction>` | Account transaction history |
| `getEvents` | `filter: GetEventsFilter` | `List<EventRecord>` | Program events in a block range, filtered by tx hash, program, and selector |
| `getAccount` | `account_id: AccountId` | `Account` | Current account state (all shards) |
| `getAccountAtBlock` | `account_id: AccountId, block_id: BlockId` | `Account` | Historical account state |
| `getAccountSummary` | `account_id: AccountId` | `AccountSummary` | Nonce, balance, and each shard's size only; safe on any account, since its size does not grow with shard contents |
| `getAccountView` | `selector: ProgramShardSelector` | `Account` | Account nonce and the one selected shard |
| `getAccountViewAtBlock` | `selector: ProgramShardSelector, block_id: BlockId` | `Account` | Historical account nonce and selected shard |
| `getStatus` | — | `IndexerStatus` | Ingestion state (`Starting`, `Syncing`, `CaughtUp`, `Error`, `Stalled`, `Halted`, with the reason where relevant) and indexed tip |
| `checkHealth` | — | `()` | Liveness check |
| `getSchema` | — | `Value` | JSON Schema of `Block` and the event types (via `schemars`). Note: this is a JSON Schema, not an OpenRPC document. An OpenRPC `describe` method is a future TODO in the code. |

**Result types:**

```rust
struct AccountSummary {
    nonce: Nonce,
    balance: Option<u128>,          // None if the native balance shard is non-canonical
    shards: List<ShardSummary>,
}

struct ShardSummary {
    program_account_id: AccountId,
    len: u64,                       // shard size in bytes
}

/// `getEvents`: with `tx_hash` set the lookup is a point query and the block range is ignored;
/// otherwise `from_block` is required, `to_block` defaults to the indexed tip, and the range
/// may span at most MAX_EVENT_QUERY_BLOCK_SPAN blocks.
struct GetEventsFilter {
    from_block: Option<BlockId>,
    to_block: Option<BlockId>,
    tx_hash: Option<HashType>,
    program_account_id: Option<AccountId>,
    selector: Option<Selector>,
}

/// `subscribeToEvents`: a live stream carries no block range.
struct EventSubscriptionFilter {
    tx_hash: Option<HashType>,
    program_account_id: Option<AccountId>,
    selector: Option<Selector>,
}

struct IndexerStatus {
    state: IndexerSyncState,
    last_error: Option<String>,
    indexed_block_id: Option<BlockId>,
    stall_reason: Option<StallReason>,        // set while Stalled
    cross_zone_halt: Option<CrossZoneHalt>,   // set while Halted
    cross_zone_peers: List<PeerStatus>,       // one per configured peer zone
}

enum IndexerSyncState { Starting, Syncing, CaughtUp, Error, Stalled, Halted }

/// The first block that broke the L2 chain.
struct StallReason {
    block_id: Option<u64>,            // None for a deserialize failure
    block_hash: Option<HashType>,
    prev_block_hash: Option<HashType>,
    l1_slot: u64,
    error: BlockIngestError,
    first_seen: Option<Timestamp>,
    orphans_since: u64,               // later non-chaining blocks seen while parked
}

/// The local block whose dispatch failed re-derivation.
struct CrossZoneHalt {
    block_id: BlockId,
    block_hash: HashType,
    src_zone: String,                 // hex
    src_block_id: u64,
    src_tx_index: u32,
    verdict: String,
}

struct PeerStatus {
    zone: String,                     // hex
    verified_tip_block_id: Option<u64>,
    cursor_slot: Option<u64>,
    stuck_slot_attempts: u32,
    health: PeerHealth,
}

enum PeerHealth { Live, Lagging, Holed, Suspended, Halted }
```

`BlockIngestError` names the failed criterion: `Deserialize`, `UnexpectedBlockId`, `BrokenChainLink`, `HashMismatch`, `EmptyBlock`, `InvalidProducerSignature`, `InvalidClockTransaction`, `InvalidFeeTransaction`, `InvalidRewardTarget`, `InvalidFeeClass`, `MissingFeeDeclaration`, `GasCapExceeded`, `RestrictedAccountModification`, `NonPublicGenesisTransaction`, or `StateTransition` (see Block acceptance criteria).
