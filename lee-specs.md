# LEE v0.3 specifications

## LEE v0.3 basic types and constants

```rust
// ---- Identifiers ----
type AccountId = [u8; 32];
type ProgramId = [u32; 8];
struct PdaSeed([u8; 32]);
/// Opaque 32-byte value that diversifies private accounts for a given (npk, vpk).
/// One key set controls up to 2^256 distinct private accounts.
type Identifier = [u8; 32];

// ---- Account contents ----
type Nonce = u128;
/// Native token amount, stored in the account's native-token shard.
type Balance = u128;
/// Bytes of one program's shard of an account; at most DATA_MAX_LENGTH.
struct ShardData(List<u8>);
type ByteString = List<u8>;
/// Borsh-encoded instruction bytes.
type InstructionData = List<u8>;
/// Borsh-encoded effect bytes, produced by a plan and consumed by an apply.
type EffectData = List<u8>;

// ---- Metering and fees ----
/// Raw zkVM cycle count or budget.
type Cycles = u64;
/// Gas amount (execution or storage work).
type Gas = u64;
/// Base-fee price or tip, in atomic units.
type Fee = u64;

// ---- Time ----
/// Sequencer-supplied block height.
type BlockId = u64;
/// Unix timestamp in milliseconds.
type Timestamp = u64;

// ---- Commitments and nullifiers ----
type Commitment = [u8; 32];
struct CommitmentSet {
    merkle_tree: MerkleTree,
    commitments: HashMap<Commitment, usize>,
    root_history: HashSet<CommitmentSetDigest>,
}
type CommitmentSetDigest = [u8; 32];
type MembershipProof = (usize, List<[u8; 32]>);

type Nullifier = [u8; 32];
type NullifierSet = BTreeSet<Nullifier>;

// ---- Private-account keys ----
type AuthorizationSecretKey = [u8; 32];   // ask; derives nsk
type NullifierSecretKey = [u8; 32];       // nsk
type NullifierPublicKey = [u8; 32];       // Npk

// ---- Note encryption (ML-KEM-768) ----
/// ML-KEM-768 encapsulation key (1184 bytes).
type ViewingPublicKey = [u8; 1184];
/// 32-byte seed for deterministic encapsulation, hash-derived per output.
type EphemeralSecretKey = [u8; 32];
/// ML-KEM-768 ciphertext (1088 bytes), sent in place of an ephemeral public key.
type EphemeralPublicKey = [u8; 1088];
/// 32-byte ML-KEM shared secret.
type SharedSecretKey = [u8; 32];
type ViewTag = u8;

struct EncryptedAccountData {
    ciphertext: Ciphertext,
    epk: EphemeralPublicKey,
    view_tag: ViewTag,
}

// ---- Signatures and proofs ----
/// BIP-340 Schnorr on secp256k1 (x-only public keys).
type Signature = [u8; 64];
type PublicKey = [u8; 32];
/// Borsh serialization of a `risc0_zkvm::InnerReceipt`.
type Proof = ByteString;

// ---- Constants ----
const DATA_MAX_LENGTH: usize = 100 * 1024;       // per shard, not per account
const MAX_NUMBER_CHAINED_CALLS: usize = 10;      // total calls ≤ this + 1
const MAX_PROGRAM_SEGMENTS: usize = 20;          // cap on a program's segment chain
const MAX_CIPHERTEXT_PADDING: u32 = 8 * 1024;    // cap on requested note padding
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const VIEWING_PUBLIC_KEY_LEN: usize = 1184;
const PRIVATE_ACCOUNT_KIND_HEADER_LEN: usize = 97;
const DEFAULT_PUBLIC_CYCLE_BUDGET: Cycles = 32 * 1024 * 1024;
const GENESIS_BLOCK_ID: BlockId = 1;

/// Reserved program addresses. These run protocol code, not guest ELFs.
const NATIVE_TOKEN_PROGRAM_ID: AccountId = [0x00; 32];
const PROGRAM_LOADER_ACCOUNT_ID: AccountId = [0xFE; 32];
```

> **Byte order:** LEE uses little-endian encoding throughout for integers, with the exception of the key protocol which follows BIP-32 (big-endian).

## Accounts

All accounts (public and private) share a common schema: a nonce and a set of *shards*, one per program that keeps state in the account.

```rust
struct Account {
    nonce: Nonce,
    data: AccountData,
}

struct AccountData {
    /// Keyed by the AccountId of the program that owns the shard.
    shards: BTreeMap<AccountId, ShardData>,
}

/// Selects one program's shard of one account.
struct ProgramShardSelector {
    account_id: AccountId,
    program_account_id: AccountId,
}

/// The default account: nonce 0 and no shards.
impl Default for Account {
    fn default() -> Self {
        Self { nonce: 0, data: AccountData { shards: BTreeMap::new() } }
    }
}
```

Every account can hold state for any number of programs, each in its own shard.

### Shards

- A shard is an arbitrary byte string of at most `DATA_MAX_LENGTH` bytes. Its content is defined by the owning program.
- **Only the owning program can write a shard.** A write is the `post_data` of an apply whose executing program is the shard's key (see [Programs](#programs)). Any other program's apply may read the shard but must leave it unchanged.
- An absent shard reads as empty. Writing an empty shard removes it, so an account's `shards` map never stores an empty value.
- Programs never see whole accounts: every program input names a `(account_id, program_account_id)` pair through a `ProgramShardSelector`, and each effect acts on exactly one shard.

Two shards are reserved for protocol code:

- **Native balance**: the shard keyed by `NATIVE_TOKEN_PROGRAM_ID`. It holds the balance as 16 bytes little-endian; an empty shard means a balance of 0, and an explicit zero encoding (16 zero bytes) is rejected as non-canonical. Only the native token program writes it, and its only operation is a transfer that debits and credits the same amount with checked arithmetic, so the total supply is conserved and no balance can overflow `u128`.
- **Loader shard**: the shard keyed by `PROGRAM_LOADER_ACCOUNT_ID`. It holds a `ProgramHeader` or a `ProgramSegment` and is written only by the program loader (see [Program deployment](#program-deployment)).

### Nonce field

The nonce is a 128-bit integer value. It has different uses depending on the visibility of the account:

- **Public accounts:** The nonce counts the number of accepted transactions in which the associated public key of the account appears as a signer, including transactions whose execution failed but was charged. This serves as a sequence number to prevent replay of transactions involving this account. Programs cannot read or change it.
- **Private accounts:** A pseudorandom value used to provide entropy for the account's commitment, making it unconditionally hiding. The initial nonce is derived from the account ID, and subsequent nonces are iteratively derived from the nullifier secret key (`nsk`) and the previous nonce. (`account_id` and `nsk` are formally defined in the [Nullifier public key derivation](#nullifier-public-key-derivation) and [Account ID](#account-id) subsections below.)

In both cases the nonce is iteratively produced: each accepted transaction increments a public account's nonce by one, and each private state update derives a fresh nonce from the previous one.

**Private account nonce initialization:**

$$\mathsf{nonce}_0 = \mathsf{SHA256}(\mathsf{account\_id} \;||\; [0_{u8}; 32])_{[0..16]}$$

where the result is the first 16 bytes of the hash, interpreted as a `u128` little-endian integer. The full preimage is 64 bytes: the 32-byte account ID followed by 32 zero bytes.

**Private account nonce update:**

$$\mathsf{nonce}_{i+1} = \mathsf{SHA256}(\mathsf{nsk} \;||\; \mathsf{nonce}_i \;||\; [0_{u8}; 16])_{[0..16]}$$

where `nonce_i` is the 16-byte little-endian encoding of the current nonce, and the result is the first 16 bytes of the hash interpreted as a `u128` little-endian integer. The full preimage is 64 bytes: 32-byte `nsk` + 16-byte nonce + 16 zero bytes.

```rust
impl Nonce {
    fn private_account_nonce_init(account_id: &AccountId) -> Self {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(account_id.value());
        // bytes[32..64] are zero
        let hash: [u8; 32] = sha256(bytes);
        Self(u128::from_le_bytes(*hash.first_chunk::<16>().unwrap()))
    }

    fn private_account_nonce_increment(self, nsk: &NullifierSecretKey) -> Self {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(nsk);
        bytes[32..48].copy_from_slice(&self.0.to_le_bytes());
        // bytes[48..64] are zero
        let hash: [u8; 32] = sha256(bytes);
        Self(u128::from_le_bytes(*hash.first_chunk::<16>().unwrap()))
    }
}
```

Private accounts use a *nullifier public key* (`Npk`) and a *viewing public key* (`vpk`) as core identifiers. The next two subsections derive `Npk` and define the account ID formats — both are prerequisites for the commitment and nullifier fields that follow.

### Nullifier public key derivation

The nullifier secret key is derived from the authorization secret key (`ask`), and the nullifier public key from the nullifier secret key, each via a domain-separated hash:

$$\mathsf{nsk} = \mathsf{SHA256}(\text{"/LEE-Keys/v1/Nullifier/Secret"} \;||\; \mathsf{ask})$$

$$\mathsf{Npk} = \mathsf{SHA256}(\text{"/LEE-Keys/v1/Nullifier/Public"} \;||\; \mathsf{nsk})$$

Each hash input is 61 bytes: a 29-byte ASCII prefix (not zero-padded) + a 32-byte key. How `ask` and the viewing key are derived from the wallet's master keys is defined by the key protocol.

```rust
impl NullifierSecretKey {
    fn from(ask: &AuthorizationSecretKey) -> Self {
        const DOMAIN: &[u8; 29] = b"/LEE-Keys/v1/Nullifier/Secret";
        let mut bytes = [0_u8; 29 + 32];
        bytes[..29].copy_from_slice(DOMAIN);
        bytes[29..].copy_from_slice(ask);
        sha256(bytes)
    }
}

impl NullifierPublicKey {
    fn from(nsk: &NullifierSecretKey) -> Self {
        const DOMAIN: &[u8; 29] = b"/LEE-Keys/v1/Nullifier/Public";
        let mut bytes = [0_u8; 29 + 32];
        bytes[..29].copy_from_slice(DOMAIN);
        bytes[29..].copy_from_slice(nsk);
        sha256(bytes)
    }
}
```

Knowledge of `ask` is what authorizes a regular private account in a transaction (see the circuit's `WitnessKind::Regular { ask }`); `nsk` alone is enough to compute update nullifiers.

### Account ID

**Public account ID:**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PUBLIC\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{public\_key})$$

```rust
/// ASCII "/LEE/v0.3/AccountId/Public/" zero-padded to 32 bytes
PUBLIC_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00"
```

**Private account ID:**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{npk} \;||\; \mathsf{vpk} \;||\; \mathsf{identifier})$$

The hash input is 1280 bytes: 32-byte prefix + 32-byte `npk` + 1184-byte `vpk` + 32-byte `identifier`. Each `(npk, vpk, identifier)` triple yields a distinct account ID, so the same set of private account keys can be reused across up to $2^{256}$ independent private accounts, one per `identifier` value.

```rust
/// ASCII "/LEE/v0.3/AccountId/Private/" zero-padded to 32 bytes
PRIVATE_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00"
```

```rust
impl AccountId {
    fn for_regular_private_account(
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        let mut bytes = [0_u8; 32 + 32 + 1184 + 32];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..1248].copy_from_slice(vpk);
        bytes[1248..1280].copy_from_slice(&identifier);
        sha256(bytes)
    }
}
```

**Public program-derived account ID (public PDA):**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PUBLIC\_PDA\_PREFIX} \;||\; \mathsf{program\_account\_id} \;||\; \mathsf{seed})$$

The hash input is 96 bytes: 32-byte prefix + 32-byte `program_account_id` (the `AccountId` the owning program is invoked at, not its `ProgramId`) + 32-byte `seed`.

```rust
/// ASCII "/LEE/v0.2/AccountId/PDA/" zero-padded to 32 bytes.
/// The "v0.2" tag is historical; changing it would move every existing public PDA.
PUBLIC_PDA_PREFIX: [u8; 32] = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00"
```

```rust
impl AccountId {
    fn for_public_pda(program_account_id: &AccountId, seed: &PdaSeed) -> Self {
        let mut bytes = [0_u8; 96];
        bytes[0..32].copy_from_slice(PUBLIC_PDA_PREFIX);
        bytes[32..64].copy_from_slice(program_account_id);
        bytes[64..96].copy_from_slice(&seed.0);
        sha256(bytes)
    }
}
```

**Private program-derived account ID (private PDA):**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_PDA\_PREFIX} \;||\; \mathsf{program\_account\_id} \;||\; \mathsf{seed} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk} \;||\; \mathsf{identifier})$$

The hash input is 1344 bytes: 32 + 32 + 32 + 32 + 1184 + 32. Unlike public PDAs, the private PDA derivation includes `Npk`, `vpk` and `identifier`. This ensures two different key holders at the same `(program_account_id, seed)` get different addresses, and a single key holder at `(program_account_id, seed, Npk, vpk)` controls a family of $2^{256}$ private PDA addresses (one per identifier value).

```rust
/// ASCII "/LEE/v0.3/AccountId/PrivatePDA/" zero-padded to 32 bytes
PRIVATE_PDA_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00"
```

```rust
impl AccountId {
    fn for_private_pda(
        program_account_id: &AccountId,
        seed: &PdaSeed,
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + 1184 + 32];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        bytes[32..64].copy_from_slice(program_account_id);
        bytes[64..96].copy_from_slice(&seed.0);
        bytes[96..128].copy_from_slice(&npk.0);
        bytes[128..1312].copy_from_slice(vpk);
        bytes[1312..1344].copy_from_slice(&identifier);
        sha256(bytes)
    }
}
```

**Private account ID from its kind.** After decrypting a note, a receiver rebuilds the account ID from the note's `PrivateAccountKind` and its own `(Npk, vpk)`:

- `Regular(identifier)` → `for_regular_private_account(npk, vpk, identifier)`
- `Pda { account_id, seed, identifier }` → `for_private_pda(account_id, seed, npk, vpk, identifier)`

**Program account IDs.** Programs are invoked at an `AccountId`: the address of their `ProgramHeader`. Besides addresses chosen freely at deploy time, the following are derived:

- *Builtin program by image ID* (`from_builtin_program`): the 32 bytes of the `ProgramId`, each `u32` word little-endian. This is a reinterpretation, not a hash. Builtins seeded at genesis live here.
- *Builtin program by name* (`from_builtin_program_name`): `SHA256(b"/LEE-BuiltinProgram/v1/AccountId" || name)`, where the prefix is exactly 32 bytes and `name` has variable length.
- *Shadow program* (`for_shadow_program`): `SHA256(SHADOW_PROGRAM_PREFIX || from_builtin_program(image_id))`, a 64-byte input. A shadow program runs only on the private path, identified by its image ID alone, and has no header.
- *Immutable mirror* (`for_immutable_mirror`): `SHA256(IMMUTABLE_MIRROR_PREFIX || header_account_id)`, a 64-byte input. It is the account ID of the private commitment that mirrors an immutable `ProgramHeader`, which lets a private transaction prove it ran a deployed program without disclosing which one.
- *Genesis segment* (genesis only): `SHA256(GENESIS_SEGMENT_ID_PREFIX || header_account_id || index_u32_le)`, a 68-byte input. It is the address of the `index`-th bytecode segment of a builtin seeded at genesis.

```rust
/// ASCII "/LEE/v0.3/AccountId/Shadow/" zero-padded to 32 bytes
SHADOW_PROGRAM_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Shadow/\x00\x00\x00\x00\x00"
/// ASCII "/LEE/v0.3/AccountId/ImmutMirror/" (exactly 32 bytes)
IMMUTABLE_MIRROR_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/ImmutMirror/"
/// ASCII "/LEE/v0.3/AccountId/GenesisSeg/" zero-padded to 32 bytes
GENESIS_SEGMENT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00"
```

### Commitment

The commitment of an account is computed as:

$$\mathsf{Commitment} = \mathsf{SHA256}(\mathsf{COMMITMENT\_PREFIX} \;||\; \mathsf{account\_id} \;||\; \mathsf{SHA256}(\mathsf{borsh}(\mathsf{account})))$$

where

- `COMMITMENT_PREFIX` is the domain separator:
  ```rust
  /// ASCII "/LEE/v0.3/Commitment/" zero-padded to 32 bytes
  COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  ```
- `account_id` is the 32-byte account ID of the private account (which encodes the owner's `npk`, `vpk` and `Identifier`; see the Account ID section above).
- `borsh(account)` is the borsh serialization of the whole `Account`: its nonce followed by its shard map.

The total preimage is 96 bytes.

```rust
impl Commitment {
    fn new(account_id: AccountId, account: &Account) -> Self {
        const COMMITMENT_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let hashed_account: [u8; 32] = sha256(borsh::to_vec(account));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMMITMENT_PREFIX);
        bytes.extend_from_slice(account_id.value());
        bytes.extend_from_slice(&hashed_account);
        sha256(bytes)
    }
}
```

### Nullifier

A private account's commitment is nullified each time the account's state is updated. There are two methods for computing a nullifier:

- **Initialization nullifier** (used when the private account is created for the first time):

  $$\mathsf{Nullifier} = \mathsf{SHA256}(\mathsf{INIT\_PREFIX} \;||\; \mathsf{account\_id})$$

  ```rust
  /// ASCII "/LEE/v0.3/Nullifier/Initialize/" zero-padded to 32 bytes
  INIT_PREFIX: [u8; 32] = b"/LEE/v0.3/Nullifier/Initialize/\x00"
  ```

- **Update nullifier** (used when an existing private account's state is updated):

  $$\mathsf{Nullifier} = \mathsf{SHA256}(\mathsf{UPDATE\_PREFIX} \;||\; \mathsf{commitment} \;||\; \mathsf{nsk})$$

  ```rust
  /// ASCII "/LEE/v0.3/Nullifier/Update/" zero-padded to 32 bytes
  UPDATE_PREFIX: [u8; 32] = b"/LEE/v0.3/Nullifier/Update/\x00\x00\x00\x00\x00"
  ```

```rust
impl Nullifier {
    fn for_account_initialization(account_id: AccountId) -> Self {
        let mut bytes = INIT_PREFIX.to_vec();
        bytes.extend_from_slice(account_id.value());
        sha256(bytes)
    }

    fn for_account_update(commitment: &Commitment, nsk: &NullifierSecretKey) -> Self {
        let mut bytes = UPDATE_PREFIX.to_vec();
        bytes.extend_from_slice(&commitment.to_byte_array());
        bytes.extend_from_slice(nsk);
        sha256(bytes)
    }
}
```

### Private account kind and encryption scheme

#### PrivateAccountKind

Every private account output is tagged with a `PrivateAccountKind` that allows the receiver to reconstruct the account ID after decryption, without storing the ID on chain:

```rust
pub enum PrivateAccountKind {
    Regular(Identifier),
    Pda {
        /// The AccountId of the program that owns the PDA.
        account_id: AccountId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}
```

The kind is serialized as a fixed 97-byte header prepended to the encrypted account data:

```
Regular(ident):                  0x00 || ident (32 bytes) || [0u8; 64]
Pda { account_id, seed, ident }: 0x01 || account_id (32 bytes) || seed (32 bytes) || ident (32 bytes)
```

Both variants produce 97 header bytes, so ciphertext lengths are uniform across account types.

After decryption the receiver reconstructs the account ID from the kind:
- `Regular(ident)` → `AccountId::for_regular_private_account(npk, vpk, ident)`
- `Pda { account_id, seed, ident }` → `AccountId::for_private_pda(account_id, seed, npk, vpk, ident)`

#### Key agreement and shared secret

Key agreement uses the ML-KEM-768 key encapsulation mechanism.

- The receiver's viewing secret key is an ML-KEM-768 seed `(d, z)` of two 32-byte values, derived by the key protocol. The viewing public key `vpk` is the 1184-byte encapsulation key obtained from that seed.
- **Sender (inside the circuit):** for each private output, derive a 32-byte ephemeral secret
  $$\mathsf{esk} = \mathsf{SHA256}(\text{"/LEE/v0.3/esk/"} \;||\; \mathsf{account\_id} \;||\; \mathsf{random\_seed} \;||\; \mathsf{nonce\_le})$$
  where `random_seed` is a 32-byte value supplied by the prover and `nonce` is the output account's new nonce (the hash input is 94 bytes; the 14-byte prefix is not padded). Then run deterministic encapsulation against `vpk` with `esk` as the encapsulation randomness. This yields the 32-byte shared secret `ss` and the 1088-byte KEM ciphertext, which is published as `epk`.
- **Receiver:** decapsulate `epk` with the decapsulation key rebuilt from `(d, z)` to recover `ss`.

For updates the nonce is derived from `nsk`, so `esk` stays unpredictable even if the prover's randomness is weak. For initializations the nonce is deterministic, so `random_seed` is the only source of entropy.

#### KDF

```rust
fn kdf(
    shared_secret: &SharedSecretKey,    // 32-byte shared secret
    nullifier: &Nullifier,              // 32-byte nullifier of this output's action
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LEE/v0.3/KDF-SHA256/");
    bytes.extend_from_slice(&shared_secret.0);
    bytes.extend_from_slice(&nullifier.to_byte_array());
    sha256(bytes)
}
```

The hash input is 84 bytes: 20-byte ASCII prefix (not zero-padded) + 32-byte shared secret + 32-byte nullifier. Each private action has a unique nullifier, so no two outputs share a key.

#### Encryption

```rust
fn encrypt(
    account: &Account,
    kind: &PrivateAccountKind,
    shared_secret: &SharedSecretKey,
    nullifier: &Nullifier,
    pad_to_len: Option<u32>,
) -> Ciphertext {
    // Plaintext: 97-byte kind header || account serialization
    let mut buffer = kind.to_header_bytes().to_vec();
    buffer.extend_from_slice(&account.to_bytes());
    // Optional floor on the plaintext length, capped at MAX_CIPHERTEXT_PADDING
    if let Some(pad_to_len) = pad_to_len {
        assert!(pad_to_len <= MAX_CIPHERTEXT_PADDING);
        if pad_to_len as usize > buffer.len() {
            buffer.resize(pad_to_len as usize, 0);
        }
    }
    // Apply ChaCha20 keystream with a [0; 12] nonce
    let key = kdf(shared_secret, nullifier);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);
    Ciphertext(buffer)
}
```

`account.to_bytes()` is `borsh(account)`: the nonce (16 bytes LE), then the shard map (u32 LE entry count, then each `(program AccountId, u32 LE length, shard bytes)` entry in ascending key order). The encoding is length-prefixed, so trailing zero padding is ignored on decryption.

#### Decryption

```rust
fn decrypt(
    ciphertext: &Ciphertext,
    shared_secret: &SharedSecretKey,
    nullifier: &Nullifier,
) -> Option<(PrivateAccountKind, Account)> {
    let mut buffer = ciphertext.0.clone();
    let key = kdf(shared_secret, nullifier);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);

    if buffer.len() < PrivateAccountKind::HEADER_LEN {
        return None;
    }
    let header: &[u8; 97] = buffer[..97].try_into().unwrap();
    let kind = PrivateAccountKind::from_header_bytes(header)?;
    // Reads one borsh Account from the front; any trailing padding is ignored.
    let account = Account::from_bytes(&buffer[97..]).ok()?;
    Some((kind, account))
}
```

## Programs

Programs define the logic for operating on accounts. They are stateless and can only change account state by emitting effects on the shards they are given. All changes to public or private accounts must be performed through program execution. There's no way to alter account state directly without invoking a program.

A program is addressed by an `AccountId`, its `program_account_id`: the address of its `ProgramHeader` (see [Program deployment](#program-deployment)). Its `ProgramId` is only the RISC Zero image ID of its bytecode, used to verify its receipts on the private path. The same bytecode deployed at two addresses is two distinct programs, each with its own shards and PDAs.

Two reserved addresses run protocol code instead of a guest ELF:

- `NATIVE_TOKEN_PROGRAM_ID` — the native token program, the only writer of native balances.
- `PROGRAM_LOADER_ACCOUNT_ID` — the program loader, the only writer of loader shards. It is public-only.

### Execution model: plan and apply

Every call runs in two phases.

1. **Plan.** The program receives its own address, its caller's address, the list of shard selectors it was given (each annotated with `is_authorized`) and the instruction data. It sees **no account state**. It returns the effects it wants applied, the chained calls it wants scheduled, validity windows and events.
2. **Apply.** Each effect is applied, in order, by a separate invocation of the *same* program. An apply receives one shard's current bytes and the effect's bytes, and returns either the new shard bytes or `None` to leave the shard unchanged. An apply may panic to abort the transaction; this is how a program rejects, for example, an insufficient balance.

```rust
struct AccountMeta {
    account_id: AccountId,
    is_authorized: bool,
    /// Which program's shard of `account_id` this input selects.
    program_account_id: AccountId,
}

struct PlanInput {
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    accounts: Vec<AccountMeta>,
    instruction_data: InstructionData,
}

struct ShardEffect {
    selector: ProgramShardSelector,
    data: EffectData,
}

struct PlanOutput {
    /// Must equal the PlanInput the program was given.
    input: PlanInput,
    effects: Vec<ShardEffect>,
    chained_calls: Vec<ChainedCall>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Dropped on the private path.
    events: Vec<ProgramEvent>,
}

struct ApplyInput {
    self_account_id: AccountId,
    selector: ProgramShardSelector,
    pre_data: ShardData,
    effect_data: EffectData,
}

struct ApplyOutput {
    /// Must equal the ApplyInput the program was given.
    input: ApplyInput,
    /// `None` keeps the shard; `Some(data)` replaces it (empty data removes it).
    post_data: Option<ShardData>,
    /// Must be empty: an apply cannot schedule calls.
    chained_calls: Vec<ChainedCall>,
}

struct ChainedCall {
    program_account_id: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    instruction_data: InstructionData,
    /// For each seed, the callee is authorized for the PDA derived from
    /// (caller's program_account_id, seed), whether public or private.
    pda_seeds: Vec<PdaSeed>,
}

struct ProgramEvent {
    /// By convention, the first 8 bytes of SHA256("<program>::<EventName>").
    selector: [u8; 8],
    data: List<u8>,
}
```

An effect may select a shard the planning program does not own. Its apply still runs under the planning program, sees that shard's bytes and must return `None`. Such an effect acts as a **guard**: the program can inspect another program's state and abort if it does not like what it sees, but cannot change it.

**Guest I/O.** A guest reads two frames: a borsh-encoded `CallKind` (`Plan = 0`, `Apply = 1`), then the borsh-encoded `PlanInput` or `ApplyInput`. It commits one frame holding a borsh-encoded `GuestOutput` (`Plan(PlanOutput)` or `Apply(ApplyOutput)`). A frame is a `u32` little-endian length followed by that many bytes. Because the output is tagged, a plan receipt can never stand in for an apply receipt under the same image ID.

### Validation of program outputs

After each plan (`validate_plan`):

1. `output.input` equals the `PlanInput` the program was given.
2. The input's shard selectors are unique.
3. Every effect's selector is one of the input's selectors.

After each apply (`validate_apply_output`):

1. `output.input` equals the `ApplyInput` the program was given.
2. If `post_data` is `Some`, the selector's `program_account_id` equals the executing program (no writes to another program's shard).
3. `chained_calls` is empty.

The traversal adds these rules:

- A chained call may only name accounts that appear in the root call's selectors (it may select a different shard of them).
- The root call plus all chained calls must not exceed `MAX_NUMBER_CHAINED_CALLS + 1` calls.
- The block and timestamp validity windows of all plans must have a non-empty intersection.

### Traversal

Public and private execution share one traversal (`ExecutionState::run`). Calls are processed depth-first: a call's chained calls run, in declared order, before its siblings.

```rust
fn run(root: RootCall, backend: &mut impl Backend) -> ExecutionOutcome {
    // One entry per account in root.shard_selectors. Private accounts start from their
    // witness; public shards are read from state the first time an effect touches them.
    let mut accounts = initialize(root);
    let mut queue = [(root_as_chained_call, /* caller */ None, /* grants */ Set::new())];
    let mut calls = 0;
    let mut windows = (unbounded, unbounded);

    while let Some((call, caller, mut grants)) = queue.pop_front() {
        assert!(calls <= MAX_NUMBER_CHAINED_CALLS);
        calls += 1;

        let mut metas = [];
        for selector in call.shard_selectors {
            let id = selector.account_id;
            assert!(accounts.contains(id)); // only root accounts
            if let Some((program, seed)) = seed_grant(caller, &call.pda_seeds, id) {
                bind_family(program, seed, id); // see "Authorization"
                grants.insert(id);
            }
            let is_authorized = credential(id) || grants.contains(id);
            metas.push(AccountMeta { account_id: id, is_authorized, program_account_id: selector.program_account_id });
        }
        let input = PlanInput { self_account_id: call.program_account_id, caller_account_id: caller,
                                accounts: metas, instruction_data: call.instruction_data };

        let plan = backend.plan(&input);
        validate_plan(&input, &plan);
        windows = windows.intersect(plan.windows); // must stay non-empty

        for effect in plan.effects {
            if is_public(effect.selector.account_id) && backend.defers_public_effects() {
                // Private path: record the effect for the sequencer to apply at settlement.
                defer(effect.selector.account_id, DeferredPublicEffect {
                    program_account_id: input.self_account_id,
                    shard_program_account_id: effect.selector.program_account_id,
                    data: effect.data,
                });
                continue;
            }
            let apply_input = ApplyInput {
                self_account_id: input.self_account_id,
                selector: effect.selector,
                pre_data: accounts.shard(effect.selector),
                effect_data: effect.data,
            };
            let output = backend.apply(&apply_input);
            validate_apply_output(&apply_input, &output);
            if let Some(data) = output.post_data {
                accounts.set_shard(effect.selector, data);
            }
        }

        for chained in plan.chained_calls.reversed() {
            queue.push_front((chained, Some(input.self_account_id), grants.clone()));
        }
        backend.complete(plan.events, windows);
    }
    finish(accounts, windows)
}
```

`backend.plan` dispatches on the callee address: the program loader and the native token program run built-in Rust; any other address is resolved to a deployed or shadow program and executed as a guest. On the public path, `complete` checks the accumulated windows against the current block and timestamp and records the call's events. On the private path, the backend verifies each plan and apply as a receipt of the claimed image instead of executing it (see [the circuit](#the-privacy-preserving-execution-circuit)).

### Authorization

`is_authorized` on an input is `credential(account) || grants.contains(account)`:

- **Credential**, fixed for the whole transaction:
  - *Public account* — its public key signed the transaction.
  - *Private regular account* — the prover supplied its authorization secret key `ask`, and `ask` derives the account's `nsk` (update) or `Npk` (init).
  - *Private PDA* — never; PDAs are authorized only through grants.
- **Grants**, accumulated along the call path. A call made with `pda_seeds` by caller `C` grants:
  - a public account whose ID equals `for_public_pda(C, seed)` for some `seed` in `pda_seeds`;
  - a private PDA whose witness is bound to `(C, seed)` for some `seed` in `pda_seeds`.

  A grant holds for that call and every call it schedules, directly or indirectly. It does not reach the caller or the caller's other chained calls.

There is no claiming step: a program owns its shard of every account by construction, so it needs no authorization to write it. `is_authorized` is information for the program, which decides what it permits. For example, the native token program refuses to debit an unauthorized sender.

**PDA family binding.** The same `(program, seed)` pair derives different private PDAs for different `(Npk, vpk, identifier)`. Without a further rule, one seed in `pda_seeds` could authorize several accounts. So across a whole transaction:

> Each `(program_account_id, seed)` pair may resolve to **at most one** account ID.

Each private PDA witness is bound to its `(program, seed)` when execution starts, and each grant (public or private) binds its pair when it is first used. A second, different account under the same pair aborts the transaction.

```rust
fn bind_family(
    bindings: &mut Map<(AccountId, PdaSeed), AccountId>,
    program_account_id: AccountId,
    seed: PdaSeed,
    account_id: AccountId,
) {
    match bindings.get((program_account_id, seed)) {
        None => bindings.insert((program_account_id, seed), account_id),
        Some(existing) => assert_eq!(existing, account_id),
    }
}
```

### Native token program

The native token program at `NATIVE_TOKEN_PROGRAM_ID` is protocol code with no ELF. On the private path the circuit recomputes it instead of verifying a receipt.

```rust
enum Instruction { Transfer { amount: Balance } }
enum Effect { Debit(Balance), Credit(Balance) }
```

- **Plan:** exactly two inputs, `[sender, recipient]`. Both select the native balance shard, they are different accounts, and the sender is authorized. The plan emits `Debit(amount)` on the sender and `Credit(amount)` on the recipient.
- **Apply:** decode the balance, then subtract or add with checked arithmetic. Underflow (insufficient balance) or overflow fails the transaction.

A program moves native tokens out of an account it controls by chaining a `Transfer` with that account's PDA seed in `pda_seeds` (`native_token::custody_transfer`).

### Validity windows

Programs can constrain when their outputs are accepted:

```rust
/// A half-open interval [from, to) with optional bounds.
/// None means unbounded on that side.
pub struct ValidityWindow<T> {
    from: Option<T>,
    to: Option<T>,
}

pub type BlockValidityWindow = ValidityWindow<BlockId>;
pub type TimestampValidityWindow = ValidityWindow<Timestamp>;
```

The traversal intersects the windows of every plan. An empty intersection fails execution. On the public path the intersection is checked against the current block and timestamp after every call. On the private path it is committed in the circuit output and checked by the sequencer.

### Metering

Public execution runs under a cycle budget shared by the whole call chain: `DEFAULT_PUBLIC_CYCLE_BUDGET`, or the budget the host derives from the transaction's `gas_limit`. Each guest session is limited to the remaining budget. The native token program and the program loader consume no cycles.

A session that halts with exit code 0 succeeds. A non-zero exit code is a failure that keeps its cycle count. A panic, a pause, or exceeding the budget (`OutOfGas`) is a failure that consumes the full budget.

## LEE v0.3 state

```rust
struct V03State {
    public_state: Map<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
}
```

- `public_state`: A map from each account ID to its `Account`. The entire `AccountId` space is conceptually populated; account IDs not explicitly stored are treated as `Account::default()` (sparse representation). Deployed programs live here too, as loader shards.
- `private_state`:
  - `CommitmentSet`: An authenticated Merkle tree of all private account commitments (including immutable-program mirrors).
  - `NullifierSet`: A `BTreeSet` of all revealed nullifiers.

The `CommitmentSet` exposes:
- `extend(commitments)` — append a batch of commitments, then record the new root in `root_history`. The root is recorded once per batch, that is once per transaction, not once per commitment.
- `get_proof_for(commitment)` — Merkle inclusion path.
- `compute_digest_for_path(commitment, proof)` — the root that a membership proof resolves to.
- `root_history.contains(digest)` — whether a digest was ever a root.

The `NullifierSet` is a plain ordered set.

### Dummy commitment and dummy commitment hash

Two special constants are derived from the default account and the null account ID `[0; 32]`:

```rust
/// DUMMY_COMMITMENT = Commitment::new(AccountId([0; 32]), &Account::default())
/// Concretely: SHA256(COMMITMENT_PREFIX || [0]*32 || SHA256([0]*20)),
/// where [0]*20 is borsh(Account::default()): a zero u128 nonce and an empty shard map (u32 length 0).
pub const DUMMY_COMMITMENT: Commitment = Commitment([
    59, 125, 5, 88, 44, 25, 75, 87, 238, 148, 130, 173, 76, 217, 13, 136, 125, 198, 106, 114, 48,
    245, 101, 6, 37, 70, 51, 208, 20, 5, 51, 18,
]);

/// DUMMY_COMMITMENT_HASH = SHA256(DUMMY_COMMITMENT)
pub const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    107, 9, 131, 34, 17, 0, 16, 21, 11, 42, 160, 50, 189, 133, 209, 183, 60, 242, 84, 238, 254, 37,
    123, 26, 90, 172, 192, 13, 95, 233, 84, 41,
];
```

`DUMMY_COMMITMENT` is the commitment of the default account (`Account::default()`) under the null account ID (`[0; 32]`). It is not a real user account: no keys exist that could spend it, so it can never be nullified.

At genesis, the `CommitmentSet` is initialized by inserting `DUMMY_COMMITMENT` as its first entry. This bootstraps the Merkle tree before any real private accounts exist and gives the set a well-defined root from the very first state. Because the Merkle tree hashes each leaf as `SHA256(value)`, the root of a tree containing only `DUMMY_COMMITMENT` is `SHA256(DUMMY_COMMITMENT)` — which is exactly `DUMMY_COMMITMENT_HASH`. As a result, `DUMMY_COMMITMENT_HASH` is permanently present in the `CommitmentSet`'s `root_history` from genesis onward.

**Role in initialization nullifiers.** Every nullifier submitted in a `PrivacyPreservingTransaction` must be paired with a `CommitmentSetDigest`. For update nullifiers this is the Merkle root that the sender's membership proof resolves to. For **init nullifiers** — emitted when a private account is created for the first time (`NullifierWitness::Init`, for both regular accounts and PDAs) — no prior commitment exists to be spent, so there is no natural Merkle root to cite; the prover supplies one (`commitment_root`). Rather than special-casing this in the sequencer's acceptance logic, init nullifiers go through the same `root_history.contains(digest)` check as update nullifiers, so any known root is accepted. `DUMMY_COMMITMENT_HASH` is always in `root_history` and therefore always valid, but wallets should cite the same current root they use for their update nullifiers: a transaction whose init nullifiers all cite `DUMMY_COMMITMENT_HASH` reveals which of its actions create new accounts. Dummy actions carry a prover-chosen root in the same way.

### Genesis

Genesis state is `V03State::default()` (empty public state, `CommitmentSet = [DUMMY_COMMITMENT]`) plus the builtin programs. Each builtin is seeded exactly as a live deploy would leave it:

- its `user_elf` is split into chunks of at most `MAX_SEGMENT_DATA_LEN` bytes, stored as `ProgramSegment`s at the genesis segment addresses (see [Account ID](#account-id));
- a `ProgramHeader` pointing at the first segment is stored at the builtin's address, by default `from_builtin_program(image_id)`;
- if the builtin is immutable, its mirror commitment is appended to the `CommitmentSet`.

## Program deployment

Programs are stored as data in public accounts, in the loader shard (`PROGRAM_LOADER_ACCOUNT_ID`):

```rust
/// Stored at the program's address.
struct ProgramHeader {
    /// The bytecode's image ID, computed from the segment chain at deploy/update time.
    image_id: ProgramId,
    /// The account holding the first bytecode segment.
    program_first_segment: AccountId,
    /// Once true, the header can never be updated again.
    immutable: bool,
}

/// One chunk of the program's user ELF, linked toward the tail.
struct ProgramSegment {
    bytecode: List<u8>,
    next_segment: Option<AccountId>,
}
```

Both are stored as plain borsh with no type tag.

**Resolution.** To run the program at address `P`, decode `P`'s loader shard as a `ProgramHeader` (none, or undecodable, means *unknown program*). Starting at `program_first_segment`, follow `next_segment` links, concatenating each segment's `bytecode`, for at most `MAX_PROGRAM_SEGMENTS` segments. The result is the user ELF; it is combined with the protocol's fixed kernel (`risc0_zkos_v1compat`) to form the executable binary. The header's stored `image_id` is used as the program's ID; it is not recomputed at dispatch.

**Program loader instructions.** The loader is invoked like any program, by a public transaction or chained call to `PROGRAM_LOADER_ACCOUNT_ID`. Every input must select the loader shard. The loader cannot run on the private path. None of its instructions may target `NATIVE_TOKEN_PROGRAM_ID` or `PROGRAM_LOADER_ACCOUNT_ID`.

```rust
enum Instruction {
    WriteSegment { bytecode: List<u8>, next_segment: Option<AccountId> },
    CreateHeader { first_segment: AccountId, immutable: bool },
    UpdateHeader { first_segment: AccountId, immutable: bool },
}
```

- **`WriteSegment`** — accounts `[target]`, or `[target, next]` when `next_segment` is `Some`. The target's loader shard must be empty; `next` must already hold a valid segment, so chains are written from the tail to the head. It requires **no authorization**. The segment must fit in `DATA_MAX_LENGTH`; `MAX_SEGMENT_DATA_LEN` (96 KiB) is the recommended chunk size.
- **`CreateHeader`** — accounts `[target, segment_1, …, segment_n]`, the chain in link order. The target's loader shard must be empty and the target must be **authorized**. `first_segment` must equal `segment_1`, the supplied accounts must be exactly the chain (at most `MAX_PROGRAM_SEGMENTS`), and the header's `image_id` is computed from the concatenated bytecode plus the kernel. It is never taken from the caller.
- **`UpdateHeader`** — same accounts and checks as `CreateHeader`, but the target must already hold a header with `immutable == false`.

When `CreateHeader` or `UpdateHeader` writes a header with `immutable == true`, the transaction also appends the header's **mirror commitment** to the `CommitmentSet`:

```rust
fn immutable_mirror_commitment(header_account_id: AccountId, header: &ProgramHeader) -> Commitment {
    let mirror = Account::default().with_shard(PROGRAM_LOADER_ACCOUNT_ID, borsh(header));
    Commitment::new(AccountId::for_immutable_mirror(header_account_id), &mirror)
}
```

A private transaction can later prove membership of this commitment to show that it ran *some* immutable deployed program without disclosing which one.

The loader's plan reads loader shards directly, including shards written earlier in the same transaction, so a single transaction can deploy a program and then call it.

**Shadow programs.** A program can also run on the private path without being deployed. Its address is `for_shadow_program(image_id)`, derived from its image ID alone, so the address itself authenticates the bytecode.

## Built-in programs

Builtins are ordinary guest programs seeded at genesis (see [Genesis](#genesis)); the native token program and the program loader are the only programs implemented in protocol code. The builtin set is defined by the host chain (LEZ). A builtin addressed by name lives at `from_builtin_program_name(name)`; otherwise it lives at `from_builtin_program(image_id)`. Additional programs are deployed with the program loader.

## Structure of a public transaction

```rust
struct Message {
    program_account_id: AccountId,
    shard_selectors: List<ProgramShardSelector>,
    nonces: List<Nonce>,
    instruction_data: InstructionData,
    /// None for a fee-exempt (system) transaction.
    fee: Option<FeeDeclaration>,
}

struct FeeDeclaration {
    /// The account debited for the fee; must sign the transaction.
    payer: AccountId,
    gas_limit: Gas,
    tip: Fee,
    max_fee: Balance,
}

type WitnessSet = List<(Signature, PublicKey)>;

struct PublicTransaction {
    message: Message,
    witness_set: WitnessSet,
}
```

The message hash prefix is:

```rust
/// ASCII "/LEE/v0.3/Message/Public/" zero-padded to 32 bytes
PREFIX: [u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00"
```

The message hash is `SHA256(PREFIX || borsh_serialize(message))`.

### Message

- `program_account_id`: The address of the program to invoke.
- `shard_selectors`: The `(account, shard)` pairs the root call receives. These accounts are the only ones any call in the chain may name. An account may appear with several shards, but each selector at most once.
- `nonces`: One nonce per signer. Each must match the current nonce of the corresponding account in state.
- `instruction_data`: Borsh-encoded instruction bytes.
- `fee`: The signed fee declaration. It is covered by the message hash, so every signature authorizes it.

### Witness set

A list of `(signature, public_key)` pairs. Each pair must be a valid BIP-340 Schnorr signature over the message hash. The accounts derived from each `public_key` (via `AccountId::from(&public_key)`) form the *signer set*. A signer's account is authorized in every call of the chain (see [Authorization](#authorization)). Upon acceptance, each signer's nonce is incremented by 1.

### Fees

LEE defines the fee fields and the metering result; the host chain (LEZ) computes and settles the fee. For a charged transaction (`fee` is `Some`), `is_fee_authorized` requires a valid signature by `fee.payer`. The host reserves the fee from the payer through a fee-settlement invocation, executes the transaction under a cycle budget derived from `gas_limit`, and refunds the unused part through a second fee-settlement invocation. Fee-settlement invocations are authorized by the fee declaration rather than by a signature, and advance no nonces.

## Structure of a privacy-preserving transaction

```rust
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
    /// Effects on this public account, in execution order, applied by the sequencer.
    effects: List<DeferredPublicEffect>,
}

struct DeferredPublicEffect {
    /// The program that planned the effect; its apply runs at settlement.
    program_account_id: AccountId,
    /// Which shard of the account the effect selects.
    shard_program_account_id: AccountId,
    data: EffectData,
}

struct PrivateAction {
    nullifier: Nullifier,
    root: CommitmentSetDigest,
    commitment: Commitment,
    encrypted_post_state: EncryptedAccountData,
}

enum ProgramImageClaim {
    /// The program at `account_id` has image `image_id`.
    Disclosed { account_id: AccountId, image_id: ProgramId },
    /// Some immutable header's mirror commitment is a member of the tree with this root.
    Undisclosed { root: CommitmentSetDigest },
}

struct WitnessSet {
    signatures_and_public_keys: List<(Signature, PublicKey)>,
    proof: Proof,
}

struct PrivacyPreservingTransaction {
    message: Message,
    witness_set: WitnessSet,
}
```

The message hash prefix is:

```rust
/// ASCII "/LEE/v0.3/Message/Privacy/" zero-padded to 32 bytes
PREFIX: [u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00"
```

The hash is `SHA256(PREFIX || borsh_serialize(message))`.

### Message

1. `public_actions`: One entry per public account of the root call, in root order, with the effects the execution deferred to that account. The message carries no public post-states: the sequencer computes them by applying these effects to live state.
2. `nonces`: One nonce per signing public account.
3. `private_actions`: One entry per private account plus any dummy actions. Each has a nullifier, the root it is checked against, a new commitment, and an encrypted note. Nullifiers and commitments are sorted **independently**, so an action's commitment is not necessarily the one its nullifier and note belong to.
4. `block_validity_window` / `timestamp_validity_window`: The intersection of all plans' windows.
5. `program_image_claims`: One claim per deployed program the proof verified receipts for (shadow programs need none).

Privacy-preserving transactions currently carry no fee declaration and are fee-exempt.

### Witness set

- `signatures_and_public_keys`: BIP-340 Schnorr signature pairs for public accounts that must be authorized.
- `proof`: A borsh-serialized `risc0_zkvm::InnerReceipt` proving correct execution of the privacy-preserving circuit.

## The privacy-preserving execution circuit

The circuit is a RISC-V program proven with the risc0 zkVM. The transaction sender executes it off-chain; the sequencer only verifies the proof. It runs the same traversal as public execution, with a backend that **verifies** each guest call instead of executing it:

1. **Plan.** For each scheduled guest call, take the next `ProvenCall` from the input and `env::verify` its `GuestOutput::Plan` journal against the image ID of the callee's address. The native token program's plan is recomputed in-circuit. A call to the program loader aborts the proof.
2. **Apply, private accounts.** For each effect on a private account, take the next apply output from the call's `ProvenCall` and verify it under the **same** image ID as the plan.
3. **Apply, public accounts.** Effects on public accounts are not applied. They are recorded as `DeferredPublicEffect`s and applied later by the sequencer. The circuit never reads public state.
4. **Outputs.** For each private witness, compute the nullifier, new nonce, commitment and encrypted note. Then add the dummy actions, sort, and commit the output.

The image ID of a callee address comes from the input:

- a `ProgramImageWitness::Disclosed { account_id, image_id }` becomes a `Disclosed` claim, which the sequencer checks against the header deployed at `account_id`;
- a `ProgramImageWitness::Undisclosed { account_id, program_header, membership_proof }` requires `program_header.immutable`, and becomes an `Undisclosed { root }` claim, where `root` is the digest the membership proof gives for the header's mirror commitment;
- a `ShadowProgramWitness { image_id }` maps `for_shadow_program(image_id)` to `image_id` and produces no claim.

An address may not be claimed twice, and no image may be claimed for `NATIVE_TOKEN_PROGRAM_ID` or `PROGRAM_LOADER_ACCOUNT_ID`. Every `ProvenCall` must be consumed.

### Circuit input

```rust
pub struct PrivacyPreservingCircuitInput {
    /// The top-level call. `authorized_accounts` lists the public signers.
    pub root: RootCall,
    /// One witness per private account of the root call.
    pub private_witnesses: Vec<PrivateWitness>,
    pub dummy_inputs: Vec<DummyInput>,
    /// Minimum plaintext length of each note, at most MAX_CIPHERTEXT_PADDING.
    pub ciphertext_padding: Option<u32>,
    pub program_image_witnesses: Vec<ProgramImageWitness>,
    pub shadow_program_witnesses: Vec<ShadowProgramWitness>,
    /// One per scheduled guest call, in traversal order.
    pub calls: Vec<ProvenCall>,
}

pub struct RootCall {
    pub program_account_id: AccountId,
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub instruction_data: InstructionData,
    pub authorized_accounts: Vec<AccountId>,
}

pub struct ProvenCall {
    pub plan: PlanOutput,
    /// Apply outputs for this call's private effects, in effect order.
    pub private_apply_outputs: Vec<ApplyOutput>,
}

pub struct PrivateWitness {
    pub vpk: ViewingPublicKey,
    /// Entropy for the note's ephemeral secret key.
    pub random_seed: [u8; 32],
    pub identifier: Identifier,
    pub kind: WitnessKind,
    pub nullifier: NullifierWitness,
}

pub enum WitnessKind {
    /// Regular private account. `ask`, if supplied, authorizes it.
    Regular { ask: Option<AuthorizationSecretKey> },
    /// Private PDA of `program_account_id` under `seed`.
    Pda { binding: (AccountId, PdaSeed) },
}

pub enum NullifierWitness {
    /// New account: pre-state is Account::default().
    Init { npk: NullifierPublicKey, commitment_root: CommitmentSetDigest },
    /// Existing account, spent with a membership proof. Npk = Npk(nsk).
    Update {
        account: Account,
        view_tag: ViewTag,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
}

pub struct DummyInput {
    pub nullifier_seed: [u8; 32],
    pub commitment_seed: [u8; 32],
    pub note: EncryptedAccountData,
    pub commitment_root: CommitmentSetDigest,
}
```

Checks on the witnesses when execution starts:

- The witness's account ID (below) is unique among witnesses and appears in the root call's selectors. Root accounts without a witness are public.
- If `ask` is supplied, `nsk(ask)` equals the `Update`'s `nsk`, or `Npk(nsk(ask))` equals the `Init`'s `npk`.
- Each `Pda` witness binds its `(program, seed)` family (see [Authorization](#authorization)).

### Circuit output

```rust
pub struct PrivacyPreservingCircuitOutput {
    pub public_actions: Vec<PublicAction>,
    pub private_actions: Vec<PrivateAction>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub program_image_claims: Vec<ProgramImageClaim>,
}

pub struct PublicAction {
    pub account_id: AccountId,
    /// Whether the account was a signer; the sequencer recomputes this.
    pub is_authorized: bool,
    pub effects: Vec<DeferredPublicEffect>,
}
```

The journal is `to_borsh_frame(output)`.

### Circuit logic summary

For each private witness (`Npk` is `npk` for `Init`, `Npk(nsk)` for `Update`):

| Witness | Account ID | Pre-state | New nonce | Nullifier, root | View tag | Authorized |
|---|---|---|---|---|---|---|
| `Regular`, `Init` | `for_regular_private_account(Npk, vpk, ident)` | default | `nonce_init(account_id)` | init nullifier, `commitment_root` | computed from `(Npk, vpk)` | iff `ask` supplied |
| `Regular`, `Update` | same | `account` | `nonce_increment(nsk)` | update nullifier of `Commitment::new(id, account)`, root from membership proof | copied from witness | iff `ask` supplied |
| `Pda`, `Init` | `for_private_pda(program, seed, Npk, vpk, ident)` | default | `nonce_init(account_id)` | init nullifier, `commitment_root` | computed | only via caller's `pda_seeds` |
| `Pda`, `Update` | same | `account` | `nonce_increment(nsk)` | update nullifier, root from membership proof | copied from witness | only via caller's `pda_seeds` |

The account's post-state is `Account { nonce: new_nonce, data: shards after execution }`. Its action is:

- `commitment = Commitment::new(account_id, post_state)`;
- `esk = EphemeralSecretKey::new(account_id, random_seed, new_nonce)`, then `(ss, epk) = encapsulate_deterministic(vpk, esk)`;
- `ciphertext = encrypt(post_state, kind, ss, nullifier, ciphertext_padding)`, where `kind` is `Regular(ident)` or `Pda { account_id: program, seed, identifier: ident }`.

For each dummy input:

- `nullifier = SHA256("/LEE/v0.3/Nullifier/Dummy/" (zero-padded to 32) || nullifier_seed)`;
- `commitment = SHA256("/LEE/v0.3/Commitment/Dummy/" (zero-padded to 32) || nullifier || commitment_seed)`;
- `root = commitment_root`, and the note is used as given (it must be at least `ciphertext_padding` bytes long).

Finally the actions are sorted by nullifier, and the list of commitments is sorted separately and reassigned in that order. This hides which commitment belongs to which nullifier and which actions are dummies. The prover is responsible for making dummy seeds and notes indistinguishable from real ones.

## Encrypted private account discovery and tagging

### Ephemeral view tags

Each private action includes a 1-byte view tag, so wallets can filter actions before attempting decapsulation:

$$\mathsf{ViewTag} = \mathsf{SHA256}(\text{"/LEE/v0.3/ViewTag/"} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk})[0]$$

where `Npk` is the 32-byte nullifier public key and `vpk` is the 1184-byte viewing public key of the recipient; the 18-byte prefix is not padded. On average only 1 in 256 actions passes this filter for a given account. For an update, the circuit copies the tag from the witness rather than recomputing it, so the prover must supply the account's correct tag.

### Private account discovery with viewing keys

For each private action of a transaction:

1. Compute the expected view tag from the wallet's `(Npk, vpk)`. Skip the action if it does not match.
2. Decapsulate `epk` with the viewing secret key `(d, z)` to get `ss`. Skip on failure.
3. Decrypt the ciphertext with `(ss, action.nullifier)`.
4. Parse the 97-byte header to recover `PrivateAccountKind`, and the rest to recover the `Account`.
5. Rebuild the account ID from the kind and the wallet's `(Npk, vpk)`.
6. Recommended: check that `Commitment::new(account_id, account)` is one of the transaction's commitments. Because commitments are shuffled, check membership in the whole list, not the entry at the same position.

```rust
fn private_account_discovery(
    tx: &PrivacyPreservingTransaction,
    vsk: &ViewingSecretKey, // (d, z)
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
) -> Vec<(PrivateAccountKind, Account)> {
    let expected_tag = EncryptedAccountData::compute_view_tag(npk, vpk);
    let commitments = tx.message.commitments();
    let mut discovered = Vec::new();

    for action in &tx.message.private_actions {
        let note = &action.encrypted_post_state;
        if note.view_tag != expected_tag {
            continue;
        }
        let Some(ss) = SharedSecretKey::decapsulate(&note.epk, &vsk.d, &vsk.z) else {
            continue;
        };
        if let Some((kind, account)) =
            EncryptionScheme::decrypt(&note.ciphertext, &ss, &action.nullifier)
        {
            let account_id = AccountId::for_private_account(npk, vpk, &kind);
            if commitments.contains(&Commitment::new(account_id, &account)) {
                discovered.push((kind, account));
            }
        }
    }
    discovered
}
```

## Domain separator summary

| Purpose | Domain separator |
|---------|-----------------|
| Commitment | `b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"` |
| Commitment — dummy | `b"/LEE/v0.3/Commitment/Dummy/\x00\x00\x00\x00\x00"` |
| Nullifier — initialization | `b"/LEE/v0.3/Nullifier/Initialize/\x00"` |
| Nullifier — update | `b"/LEE/v0.3/Nullifier/Update/\x00\x00\x00\x00\x00"` |
| Nullifier — dummy | `b"/LEE/v0.3/Nullifier/Dummy/\x00\x00\x00\x00\x00\x00"` |
| Account ID — public | `b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00"` |
| Account ID — private | `b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00"` |
| Account ID — public PDA | `b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00"` (historical v0.2 tag) |
| Account ID — private PDA | `b"/LEE/v0.3/AccountId/PrivatePDA/\x00"` |
| Account ID — shadow program | `b"/LEE/v0.3/AccountId/Shadow/\x00\x00\x00\x00\x00"` |
| Account ID — immutable mirror | `b"/LEE/v0.3/AccountId/ImmutMirror/"` |
| Account ID — genesis segment | `b"/LEE/v0.3/AccountId/GenesisSeg/\x00"` |
| Account ID — builtin program by name | `b"/LEE-BuiltinProgram/v1/AccountId"` |
| Nullifier secret key (from ask) | `b"/LEE-Keys/v1/Nullifier/Secret"` (29 bytes, unpadded) |
| Nullifier public key (from nsk) | `b"/LEE-Keys/v1/Nullifier/Public"` (29 bytes, unpadded) |
| Ephemeral secret key | `b"/LEE/v0.3/esk/"` (14 bytes, unpadded) |
| KDF | `b"LEE/v0.3/KDF-SHA256/"` |
| View tag | `b"/LEE/v0.3/ViewTag/"` |
| Public transaction message hash | `b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00"` |
| Privacy transaction message hash | `b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00"` |

## Public transaction acceptance criteria

For a public transaction to be accepted and applied to the state:

- **Signature/nonce count match:** The number of nonces equals the number of `(signature, public_key)` pairs.
- **No duplicate signers:** No account appears twice in the signer set.
- **Valid signatures:** All BIP-340 Schnorr signatures verify against the message hash.
- **Nonce checks:** For each signer, the nonce in the transaction matches the account's current nonce.
- **Non-empty, unique selectors:** `shard_selectors` has at least one entry and no repeated `(account_id, program_account_id)` pair.
- **Program existence:** `program_account_id` is the native token program, the program loader, or resolves to a deployed program.
- **Valid execution:** The traversal (see [Programs](#programs)) completes: every plan and apply passes validation, every chained call names only root accounts, the call count stays within `MAX_NUMBER_CHAINED_CALLS + 1`, no PDA family is bound twice, and no guest fails or runs out of budget.
- **Validity windows:** After every call, the intersection of the windows so far contains the current `block_id` and `timestamp`.

The result is a state diff: the post-state of every shard an effect touched, the signers whose nonces advance, any mirror commitments written by the program loader, and the emitted events.

**Charging.** When the host executes with metering (`from_public_transaction_metered`):

- A failed signature or nonce check, malformed input, or an unknown top-level program rejects the transaction. It is not included and not charged.
- Any other failure (a guest panic or non-zero exit, `OutOfGas`, too many chained calls, a failed validation, an out-of-window output, an unknown program in a chained call) **reverts** the execution but is charged: the diff keeps only the signers' nonce increments.

In pseudocode:

```rust
fn validate_and_produce_public_state_diff(
    tx: PublicTransaction,
    state: V03State,
    block_id: BlockId,
    timestamp: Timestamp,
    cycle_budget: Cycles,
) -> StateDiff {
    let message = tx.message;

    // Authenticate signers
    assert_eq!(message.nonces.len(), tx.witness_set.len());
    let signers = tx.witness_set.map(|(_, pk)| AccountId::from(pk));
    assert_no_duplicates(signers);
    for ((signature, public_key), nonce) in tx.witness_set.zip(message.nonces) {
        assert!(signature.is_valid_for(message.hash(), public_key));
        assert_eq!(state.get_account(AccountId::from(public_key)).nonce, nonce);
    }

    // Execute
    assert!(!message.shard_selectors.is_empty());
    assert_no_duplicates(message.shard_selectors);
    let outcome = run(
        RootCall {
            program_account_id: message.program_account_id,
            shard_selectors: message.shard_selectors,
            instruction_data: message.instruction_data,
            authorized_accounts: signers,
        },
        &mut PublicBackend::new(state, block_id, timestamp, cycle_budget),
    );

    StateDiff {
        signer_account_ids: signers,
        // For each root public account: its current state with the touched shards replaced.
        public_diff: outcome.public.map(|(id, shards)| (id, state.get_account(id).updated_with(shards))),
        new_commitments: outcome.loader_mirror_commitments,
        new_nullifiers: [],
        events: outcome.events,
    }
}
```

### Note on replay attacks

The nonce mechanism ensures authorized public transactions cannot be replayed. Once accepted, whether it succeeded or was charged for a failure, the nonces of all signers are incremented, so the same transaction can never be valid again. Transactions with no signers (fee-exempt system transactions) could in principle be replayed; the host is responsible for admitting them.

## Privacy-preserving transaction acceptance criteria

For a privacy-preserving transaction to be accepted:

- **Non-empty:** `private_actions` is not empty.
- **No duplicate public accounts:** No account ID appears twice in `public_actions`.
- **No duplicate nullifiers or commitments** within the transaction.
- **Signatures and nonces:** The same rules as for public transactions: counts match, no duplicate signers, valid signatures, matching nonces.
- **Validity windows:** The current `block_id` and `timestamp` fall within the message's windows.
- **Program image claims:** For each `Disclosed { account_id, .. }` claim, a program is deployed at `account_id`; the claim is rebuilt with that header's `image_id`, not the one in the message. For each `Undisclosed { root }` claim, `root` is in `root_history`.
- **Proof verification:** The proof verifies against `PRIVACY_PRESERVING_CIRCUIT_ID` and the circuit output rebuilt from the message. In that output, each public action's `is_authorized` is recomputed as "the account is a signer", and the claims are the rebuilt ones.
- **Commitment freshness:** No new commitment is already in the `CommitmentSet`.
- **Nullifier validity:** No nullifier is already in the `NullifierSet`, and each nullifier's root is in `root_history`.
- **Settlement:** The deferred public effects apply cleanly. For each public action, in order, each effect is applied to the account's current shard by the program resolved at the effect's `program_account_id` (the native token program is recomputed), under one shared `DEFAULT_PUBLIC_CYCLE_BUDGET`. Each apply output must pass `validate_apply_output`.

In pseudocode:

```rust
fn verify_privacy_preserving_transaction(
    tx: PrivacyPreservingTransaction,
    state: V03State,
    block_id: BlockId,
    timestamp: Timestamp,
) -> StateDiff {
    let message = tx.message;
    let witness_set = tx.witness_set;

    assert!(!message.private_actions.is_empty());
    assert_no_duplicates(message.public_account_ids());
    assert_no_duplicates(message.nullifiers().map(|(n, _)| n));
    assert_no_duplicates(message.commitments());

    // Signatures and nonces
    assert_eq!(message.nonces.len(), witness_set.signatures_and_public_keys.len());
    let signers = witness_set.signatures_and_public_keys.map(|(_, pk)| AccountId::from(pk));
    assert_no_duplicates(signers);
    for ((sig, pk), nonce) in witness_set.signatures_and_public_keys.zip(message.nonces) {
        assert!(sig.is_valid_for(message.hash(), pk));
        assert_eq!(state.get_account(AccountId::from(pk)).nonce, nonce);
    }

    assert!(message.block_validity_window.is_valid_for(block_id));
    assert!(message.timestamp_validity_window.is_valid_for(timestamp));

    // Anchor program image claims to chain state
    let claims = message.program_image_claims.map(|claim| match claim {
        Disclosed { account_id, .. } => Disclosed {
            account_id,
            image_id: state.get_program_image_id(account_id).expect("unknown program"),
        },
        Undisclosed { root } => {
            assert!(state.commitment_set.root_history.contains(root));
            Undisclosed { root }
        }
    });

    // Proof
    let output = PrivacyPreservingCircuitOutput {
        public_actions: message.public_actions.map(|a| PublicAction {
            account_id: a.account_id,
            is_authorized: signers.contains(a.account_id),
            effects: a.effects,
        }),
        private_actions: message.private_actions,
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
        program_image_claims: claims,
    };
    assert!(witness_set.proof.verifies(PRIVACY_PRESERVING_CIRCUIT_ID, to_borsh_frame(output)));

    // Freshness
    for commitment in message.commitments() {
        assert!(!state.commitment_set.contains(commitment));
    }
    for (nullifier, root) in message.nullifiers() {
        assert!(!state.nullifier_set.contains(nullifier));
        assert!(state.commitment_set.root_history.contains(root));
    }

    // Settle deferred public effects against live state
    let public_diff = apply_public_effects(state, message.public_actions, DEFAULT_PUBLIC_CYCLE_BUDGET);

    StateDiff {
        signer_account_ids: signers,
        public_diff,
        new_commitments: message.commitments(),
        new_nullifiers: message.nullifiers().map(|(n, _)| n),
        events: [],
    }
}
```

### Note on replay attacks

Replay attacks are not possible for privacy-preserving transactions. Every accepted transaction reveals at least one nullifier, so a replay is rejected by the nullifier checks.

## State transitions

Both transaction kinds produce a validated `StateDiff`, which is applied the same way:

1. Replace each account in `public_diff`.
2. Increment the nonce of every signer by 1.
3. Append the new commitments to the `CommitmentSet` as one batch, then record the new root in `root_history`.
4. Add the new nullifiers to the `NullifierSet`.

```rust
fn apply_state_diff(state: &mut V03State, diff: StateDiff) -> Vec<TransactionEvent> {
    for (account_id, account) in diff.public_diff {
        state.public_state[account_id] = account;
    }
    for account_id in diff.signer_account_ids {
        state.public_state[account_id].nonce += 1;
    }
    state.private_state.0.extend(diff.new_commitments);
    state.private_state.1.extend(diff.new_nullifiers);
    diff.events
}
```

Validation happens entirely before this step, so a rejected transaction changes nothing. A charged failure yields a diff containing only the signers' nonce increments.

Programs are deployed by ordinary public transactions to the program loader (see [Program deployment](#program-deployment)); there is no separate deployment transaction.
