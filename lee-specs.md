# LEE v0.3 specifications

## LEE v0.3 basic types and constants

```rust
// ---- Identifiers ----
type AccountId = [u8; 32];
type ProgramId = [u32; 8];
struct PdaSeed([u8; 32]);
/// Identifies one program's actor state in one account: the program at `program_account_id` acting on `account_id`.
struct Actor {
    account_id: AccountId,
    program_account_id: AccountId,
}

// ---- Account contents ----
type Nonce = u128;
/// Native token amount, stored in the account's native balance actor state.
type Balance = u128;
/// Bytes of one program's actor state in an account.
struct ActorState(List<u8>);
/// Borsh-encoded message payload bytes.
type MessageData = List<u8>;

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
    /// Each commitment's leaf index in the tree.
    commitments: Map<Commitment, usize>,
    root_history: Set<CommitmentSetDigest>,
}
type CommitmentSetDigest = [u8; 32];
type CommitmentPosition = u64;
type MembershipProof = (CommitmentPosition, List<[u8; 32]>);

type Nullifier = [u8; 32];
type NullifierSet = Set<Nullifier>;

// ---- Private-account keys ----
type AuthorizationSecretKey = [u8; 32];   // ask; derives nsk
type NullifierSecretKey = [u8; 32];       // nsk
type NullifierPublicKey = [u8; 32];       // Npk

// ---- Note encryption (ML-KEM-768) ----
/// ML-KEM-768 encapsulation key (`VIEWING_PUBLIC_KEY_LEN` = 1184 bytes).
type ViewingPublicKey = [u8; VIEWING_PUBLIC_KEY_LEN];
/// 32-byte seed for deterministic encapsulation, hash-derived per output.
type EphemeralSecretKey = [u8; 32];
/// ML-KEM-768 ciphertext (`ML_KEM_768_CIPHERTEXT_LEN` = 1088 bytes), sent in place of an ephemeral public key.
type EphemeralPublicKey = [u8; ML_KEM_768_CIPHERTEXT_LEN];
/// 32-byte ML-KEM shared secret.
type SharedSecretKey = [u8; 32];
struct Ciphertext(List<u8>);

struct EncryptedNote {
    ciphertext: Ciphertext,
    epk: EphemeralPublicKey,
}

// ---- Public account signing keys (see the key protocol) ----
enum KeyType { Schnorr = 0 }
type KeyCommitment = [u8; 32];
/// An account's current authorization key: 33 bytes (key type || commitment).
struct SigningKeyState {
    key_type: KeyType,
    key_commitment: KeyCommitment,
}
/// BIP-340 Schnorr on secp256k1 (x-only public keys).
type Signature = [u8; 64];
type PublicKey = [u8; 32];

// ---- Proofs ----
/// Borsh serialization of a `risc0_zkvm::InnerReceipt`.
type Proof = List<u8>;

// ---- Constants ----
const MAX_PROGRAM_SEGMENTS: usize = 20;          // cap on a program's segment chain
const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;   // chunk size for splitting a program into segments (client-side, not checked)
const MAX_CIPHERTEXT_PADDING: u32 = 8 * 1024;    // cap on requested note padding
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const VIEWING_PUBLIC_KEY_LEN: usize = 1184;
const PRIVATE_ACCOUNT_KIND_HEADER_LEN: usize = 65;
const DEFAULT_PUBLIC_CYCLE_BUDGET: Cycles = 32 * 1024 * 1024;
const GENESIS_BLOCK_ID: BlockId = 1;

/// Reserved program addresses.
const NATIVE_TOKEN_PROGRAM_ID: AccountId = [0x00; 32];
const SYSTEM_UPGRADER_ACCOUNT_ID: AccountId = [0xFD; 32];
const PROGRAM_LOADER_ACCOUNT_ID: AccountId = [0xFE; 32];
```

> **Byte order:** LEE uses little-endian encoding throughout for integers, with the exception of the key protocol which follows BIP-32 (big-endian).

## Accounts

All accounts (public and private) share a common schema: a nonce and a set of *actor states*, one per program that keeps state in the account.

```rust
struct Account {
    nonce: Nonce,
    data: AccountData,
}

struct AccountData {
    /// Keyed by the AccountId of the program that owns the actor state.
    actor_states: BTreeMap<AccountId, ActorState>,
}

/// The default account: nonce 0 and no actor states.
impl Default for Account {
    fn default() -> Self {
        Self { nonce: 0, data: AccountData { actor_states: BTreeMap::new() } }
    }
}
```

The pair of an account and a program is an *actor* (`Actor { account_id, program_account_id }`): the program at `program_account_id` acting on the account `account_id`, with that account's actor state for the program as its state.

### Actor states

- An actor state is an arbitrary byte string. Its content is defined by the owning program.
- **Only the owning program can write to an actor state.** A program handling a message receives only its own actor's state (`pre_state`) and may replace only that state. To read another program's actor state, a program sends that program a message.
- If an account has no entry for a program in its `actor_states` map, that program's actor state is empty bytes. Writing empty bytes to an actor state removes its entry, so the `actor_states` map never stores an empty value.

Some actor states are reserved for protocol use. Apart from the initial state set at [genesis](#genesis), each is written only as follows:

- **Native balance:** the actor state keyed by `NATIVE_TOKEN_PROGRAM_ID`, written only by the native token program.
- **Signing key state:** for public accounts, the actor state keyed by the signature program's address, holding the account's `SigningKeyState`. It is written only at settlement, never by a program (see the key protocol).
- **Loader state:** the actor state keyed by `PROGRAM_LOADER_ACCOUNT_ID`, written only by the program loader (see [Program deployment](#program-deployment)).

### Nonce field

The nonce is a 128-bit integer value. It has different uses depending on the visibility of the account:

- **Public accounts:** The nonce counts the number of accepted transactions the account has signed, including transactions whose execution failed but was charged. This serves as a sequence number to prevent replay of transactions involving this account. Each signed transaction also rotates the account's authorization key (see the key protocol). Programs cannot read or change it.
- **Private accounts:** A pseudorandom value used to provide entropy for the account's commitment, so that the commitment hides the account's state. Every nonce is derived from the nullifier secret key (`nsk`) and the previous nonce. (`nsk` is formally defined in the [Nullifier public key derivation](#nullifier-public-key-derivation) subsection below.)

In both cases the nonce is iteratively produced: each accepted transaction (with the account as the signer) increments a public account's nonce by one, and each private state update derives a fresh nonce from the previous one.

**Private account nonce:** each private state update derives the next nonce from `nsk` and the current nonce:

$$\mathsf{nonce}_{i+1} = \mathsf{SHA256}(\mathsf{nsk} \;||\; \mathsf{nonce}_i \;||\; [0_{u8}; 16])_{[0..16]}$$

where `nonce_i` is the 16-byte little-endian encoding of the current nonce, and the result is the first 16 bytes of the hash interpreted as a `u128` little-endian integer. The full preimage is 64 bytes: 32-byte `nsk` + 16-byte nonce + 16 zero bytes. A private account starts from the default account, whose nonce is 0, so its first nonce is this update applied to nonce 0.

```rust
impl Nonce {
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

Private accounts use a *nullifier public key* (`Npk`) and a *viewing public key* (`vpk`) as core identifiers. The next two subsections derive `Npk` and define the account ID formats — both are prerequisites for the commitment and nullifier sections that follow.

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

A regular private account's witness holds one of three keys (`RegularKey`):

- `Authorized(ask)`: authorizes the account's actors listed in the witness's `signer_programs`.
- `Nullifying(nsk)`: updates the account without authorizing it. `nsk` computes the nullifier that spends the account's current commitment and derives its next nonce, so such an update can only make changes that need no authorization.
- `FeeOnly(ask)`: authorizes only the transaction's fee entry.

A private PDA's witness holds only its `nsk`; its authority comes from its program's seed, not from `ask`.

### Account ID

**Public account ID:** derived from the commitment to the account's nonce-0 authorization key (`c_0`), with a prefix specific to its signing key type. It does not change when the account's key rotates. The derivation and its key-type prefixes are defined by the key protocol.

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PUBLIC\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{SHA256}(\mathsf{key\_type\_prefix} \;||\; c_0))$$

```rust
/// ASCII "/LEE/v0.3/AccountId/Public/" zero-padded to 32 bytes
PUBLIC_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00"
```

**Private account ID:**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk})$$

The hash input is 1248 bytes: 32-byte prefix + 32-byte `Npk` + `VIEWING_PUBLIC_KEY_LEN`-byte (1184) `vpk`.

```rust
/// ASCII "/LEE/v0.3/AccountId/Private/" zero-padded to 32 bytes
PRIVATE_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00"
```

```rust
impl AccountId {
    fn for_regular_private_account(npk: &NullifierPublicKey, vpk: &ViewingPublicKey) -> Self {
        let mut bytes = [0_u8; 32 + 32 + VIEWING_PUBLIC_KEY_LEN];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..].copy_from_slice(vpk);
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

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_PDA\_PREFIX} \;||\; \mathsf{program\_account\_id} \;||\; \mathsf{seed} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk})$$

The hash input is 1312 bytes: 32 + 32 + 32 + 32 + `VIEWING_PUBLIC_KEY_LEN` (1184). Unlike public PDAs, the private PDA derivation includes `Npk` and `vpk`, so the same `(program, seed)` gives a different account for each holder of the keys.

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
    ) -> Self {
        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + VIEWING_PUBLIC_KEY_LEN];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        bytes[32..64].copy_from_slice(program_account_id);
        bytes[64..96].copy_from_slice(&seed.0);
        bytes[96..128].copy_from_slice(&npk.0);
        bytes[128..].copy_from_slice(vpk);
        sha256(bytes)
    }
}
```

**Private account ID from its kind.** After decrypting a note, a receiver rebuilds the account ID from the note's `PrivateAccountKind` and its own `(Npk, vpk)`:

- `Regular` → `for_regular_private_account(Npk, vpk)`
- `Pda { account_id, seed }` → `for_private_pda(account_id, seed, Npk, vpk)`

**Blinded address.** A private account can be named without revealing it, by an address blinded with a 32-byte factor known only to those it is shared with:

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{BLINDED\_PREFIX} \;||\; \mathsf{account\_id} \;||\; \mathsf{factor})$$

The hash input is 96 bytes.

```rust
/// ASCII "/LEE/v0.3/AccountId/Blinded/" zero-padded to 32 bytes
BLINDED_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Blinded/\x00\x00\x00\x00"
```

**Program account IDs.** Programs are invoked at an `AccountId`: the address of their `ProgramHeader`. Besides addresses chosen freely at deploy time, the following are derived:

- *Builtin program by image ID* (`from_builtin_program`): the 32 bytes of the `ProgramId`, each `u32` word little-endian. This is a reinterpretation, not a hash. Used to derive shadow-program addresses and by test harnesses; system programs are addressed by name (below).
- *System program* (`from_system_program_name`): the public PDA of `SYSTEM_UPGRADER_ACCOUNT_ID` whose seed is `SHA256(SYSTEM_PROGRAM_SEED_PREFIX || name)`, where `name` is the program's `SystemProgramName` (1 to 32 bytes, zero-padded to 32). The seed's hash input is 64 bytes.
- *Shadow program* (`for_shadow_program`): `SHA256(SHADOW_PROGRAM_PREFIX || from_builtin_program(image_id))`, a 64-byte input. A shadow program runs only on the private path, identified by its image ID alone, and has no header.
- *Immutable mirror* (`for_immutable_mirror`): `SHA256(IMMUTABLE_MIRROR_PREFIX || header_account_id)`, a 64-byte input. It is the account ID of the private commitment that mirrors an immutable `ProgramHeader`, which lets a private transaction prove it ran a deployed program without disclosing which one.
- *Genesis segment* (genesis only): `SHA256(GENESIS_SEGMENT_ID_PREFIX || header_account_id || index_u32_le)`, a 68-byte input. It is the address of the `index`-th bytecode segment of a builtin seeded at genesis.

```rust
/// ASCII "/LEE/SystemUpgrader/v1/Name" zero-padded to 32 bytes
SYSTEM_PROGRAM_SEED_PREFIX: [u8; 32] = b"/LEE/SystemUpgrader/v1/Name\x00\x00\x00\x00\x00"
/// ASCII "/LEE/v0.3/AccountId/Shadow/" zero-padded to 32 bytes
SHADOW_PROGRAM_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Shadow/\x00\x00\x00\x00\x00"
/// ASCII "/LEE/v0.3/AccountId/ImmutMirror/" (exactly 32 bytes)
IMMUTABLE_MIRROR_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/ImmutMirror/"
/// ASCII "/LEE/v0.3/AccountId/GenesisSeg/" zero-padded to 32 bytes
GENESIS_SEGMENT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00"
```

```rust
impl AccountId {
    /// The 32 bytes of the image ID, each u32 word little-endian (a reinterpretation, not a hash).
    fn from_builtin_program(image_id: ProgramId) -> Self {
        let mut bytes = [0_u8; 32];
        for (i, word) in image_id.iter().enumerate() {
            bytes[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        AccountId(bytes)
    }

    fn from_system_program_name(name: &SystemProgramName) -> Self {
        let mut bytes = [0_u8; 64];
        bytes[0..32].copy_from_slice(SYSTEM_PROGRAM_SEED_PREFIX);
        bytes[32..64].copy_from_slice(name.as_bytes());
        Self::for_public_pda(&SYSTEM_UPGRADER_ACCOUNT_ID, &PdaSeed(sha256(bytes)))
    }

    fn for_shadow_program(image_id: &ProgramId) -> Self {
        let mut bytes = [0_u8; 64];
        bytes[0..32].copy_from_slice(SHADOW_PROGRAM_PREFIX);
        bytes[32..64].copy_from_slice(AccountId::from_builtin_program(*image_id).value());
        sha256(bytes)
    }
}
```

The signature program, which holds every public account's signing key state, is the system program named `signature`.

### Commitment

The commitment of an account is computed as follows (message commitments are defined below; dummy actions use a separate derivation, see [Dummy actions](#dummy-actions)):

$$\mathsf{Commitment} = \mathsf{SHA256}(\mathsf{COMMITMENT\_PREFIX} \;||\; \mathsf{account\_id} \;||\; \mathsf{SHA256}(\mathsf{borsh}(\mathsf{account})))$$

where

- `COMMITMENT_PREFIX` is the domain separator:
  ```rust
  /// ASCII "/LEE/v0.3/Commitment/" zero-padded to 32 bytes
  COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  ```
- `account_id` is the 32-byte account ID of the private account (which encodes the owner's `Npk` and `vpk`; see the Account ID section above), or, for an immutable program's mirror commitment, the mirror's account ID (see [Program deployment](#program-deployment)).
- `borsh(account)` is the borsh serialization of the whole `Account`: its nonce followed by its actor-state map.

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

**Message commitments.** Asynchronous messages published to the commitment set are committed to by their body (`MessageBody`: sender actor, destination actor and message data), either in the clear or sealed under a hiding randomness `rho`:

$$\mathsf{Commitment} = \mathsf{SHA256}(\mathsf{MESSAGE\_COMMITMENT\_PREFIX} \;||\; \mathsf{SHA256}(\mathsf{borsh}(\mathsf{body})))$$

$$\mathsf{Commitment} = \mathsf{SHA256}(\mathsf{SEALED\_COMMITMENT\_PREFIX} \;||\; \mathsf{SHA256}(\mathsf{borsh}(\mathsf{body})) \;||\; \mathsf{rho})$$

The preimages are 64 and 96 bytes. A sealed message's `rho` is derived from the shared secret of the note that carries it to its recipient, so only the sender and the recipient can open the commitment.

```rust
/// ASCII "/LEE/v0.3/Commitment/Message/" zero-padded to 32 bytes
MESSAGE_COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/Message/\x00\x00\x00"
/// ASCII "/LEE/v0.3/Commitment/Sealed/" zero-padded to 32 bytes
SEALED_COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/Sealed/\x00\x00\x00\x00"
```

### Nullifier

Every private action reveals a nullifier, and the state rejects any nullifier already in its `NullifierSet`. Private accounts use one kind of nullifier, and privately received messages a second (dummy actions use a third; see [Dummy actions](#dummy-actions)):

- **Account nullifier** (used whenever a private account's state is updated):

  $$\mathsf{Nullifier} = \mathsf{SHA256}(\mathsf{UPDATE\_PREFIX} \;||\; \mathsf{commitment} \;||\; \mathsf{nsk})$$

  ```rust
  /// ASCII "/LEE/v0.3/Nullifier/Update/" zero-padded to 32 bytes
  UPDATE_PREFIX: [u8; 32] = b"/LEE/v0.3/Nullifier/Update/\x00\x00\x00\x00\x00"
  ```

  The preimage is 96 bytes. Including `nsk` means only the key holder can spend the commitment, and an observer cannot link the nullifier to the commitment it spends.

  An initialization spends the account nullifier of the account's commitment as the default account (`Commitment::new(account_id, &Account::default())`). This commitment is never inserted in the commitment set, but its nullifier marks the account as created; like any account nullifier, only the holder of `nsk` can compute it.

- **Message nullifier** (used when a private account receives a message published to the commitment set):

  $$\mathsf{Nullifier} = \mathsf{SHA256}(\mathsf{MESSAGE\_PREFIX} \;||\; \mathsf{nsk} \;||\; \mathsf{commitment} \;||\; \mathsf{position})$$

  ```rust
  /// ASCII "/LEE/v0.3/Nullifier/Message/" zero-padded to 32 bytes
  MESSAGE_PREFIX: [u8; 32] = b"/LEE/v0.3/Nullifier/Message/\x00\x00\x00\x00"
  ```

  The preimage is 104 bytes: `nsk` is the receiving account's, `commitment` is the message's commitment and `position` (8 bytes, little-endian) is its position in the commitment set. The same message can be published at several positions; the position gives each its own nullifier.

```rust
impl Nullifier {
    fn for_account_update(commitment: &Commitment, nsk: &NullifierSecretKey) -> Self {
        let mut bytes = UPDATE_PREFIX.to_vec();
        bytes.extend_from_slice(&commitment.to_byte_array());
        bytes.extend_from_slice(nsk);
        sha256(bytes)
    }

    fn for_account_initialization(account_id: &AccountId, nsk: &NullifierSecretKey) -> Self {
        Self::for_account_update(&Commitment::new(account_id, &Account::default()), nsk)
    }

    fn for_message(
        nsk: &NullifierSecretKey,
        commitment: &Commitment,
        position: CommitmentPosition,
    ) -> Self {
        let mut bytes = [0_u8; 104];
        bytes[..32].copy_from_slice(MESSAGE_PREFIX);
        bytes[32..64].copy_from_slice(nsk);
        bytes[64..96].copy_from_slice(&commitment.to_byte_array());
        bytes[96..].copy_from_slice(&position.to_le_bytes());
        sha256(bytes)
    }
}
```

### Private account kind and encryption scheme

#### PrivateAccountKind

Every private account output is tagged with a `PrivateAccountKind` that allows the receiver to reconstruct the account ID after decryption, without storing the ID on chain:

```rust
enum PrivateAccountKind {
    Regular,
    Pda {
        /// The AccountId of the program that owns the PDA.
        account_id: AccountId,
        seed: PdaSeed,
    },
}
```

The kind is serialized as a fixed `PRIVATE_ACCOUNT_KIND_HEADER_LEN`-byte header prepended to the encrypted account data:

```
Regular:                  0x00 || [0u8; 64]
Pda { account_id, seed }: 0x01 || account_id (32 bytes) || seed (32 bytes)
```

The constant length of the header guarantees that a ciphertext's length does not reveal whether the account is regular or a PDA.

After decryption the receiver reconstructs the account ID from the kind:
- `Regular` → `AccountId::for_regular_private_account(Npk, vpk)`
- `Pda { account_id, seed }` → `AccountId::for_private_pda(account_id, seed, Npk, vpk)`

#### Key agreement and shared secret

Key agreement uses the ML-KEM-768 key encapsulation mechanism.

- The receiver's viewing secret key is an ML-KEM-768 seed `(d, z)` of two 32-byte values, derived by the key protocol. The viewing public key `vpk` is the `VIEWING_PUBLIC_KEY_LEN`-byte encapsulation key obtained from that seed.
- **Sender (inside the circuit):** for each private output, derive a 32-byte ephemeral secret
  $$\mathsf{esk} = \mathsf{SHA256}(\text{"/LEE/v0.3/esk/"} \;||\; \mathsf{account\_id} \;||\; \mathsf{random\_seed} \;||\; \mathsf{nonce\_le})$$
  where `random_seed` is a 32-byte value supplied by the prover and `nonce` is the output account's new nonce (the hash input is 94 bytes; the 14-byte prefix is not padded). Then run deterministic encapsulation against `vpk` with `esk` as the encapsulation randomness. This yields the 32-byte shared secret `ss` and the `ML_KEM_768_CIPHERTEXT_LEN`-byte KEM ciphertext, which is published as `epk`.
- **Receiver:** decapsulate `epk` with the decapsulation key rebuilt from `(d, z)` to recover `ss`.

Every private nonce is derived from `nsk` (see [Nonce field](#nonce-field)), so `esk` stays unpredictable even if the prover's randomness is weak.

#### KDF

The KDF turns the ML-KEM shared secret into the ChaCha20 key for one note. The sender computes it in the circuit and the receiver after decapsulating `epk`; both know the action's nullifier, which is published with the note.

Because nullifiers never repeat, every note gets its own key, even if two encapsulations produced the same shared secret. This is what makes the fixed zero ChaCha20 nonce safe.

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

The hash input is 84 bytes: 20-byte ASCII prefix (not zero-padded) + 32-byte shared secret + 32-byte nullifier.

A privacy-preserving transaction whose fee payer is private also carries a *fee fallback* note: the payer's state after the fee transfer alone, which settlement applies instead of the payer's main note when the public part of the transaction fails. The fallback shares the main note's shared secret and nullifier, so its key is derived under its own 29-byte prefix, `b"LEE/v0.3/KDF-SHA256/Fallback/"`, in place of `b"LEE/v0.3/KDF-SHA256/"`.

#### Encryption

The circuit encrypts each private output's note, passing `ciphertext_padding` as `pad_to_len`.

```rust
fn encrypt(
    account: &Account,
    kind: &PrivateAccountKind,
    shared_secret: &SharedSecretKey,
    nullifier: &Nullifier,
    pad_to_len: Option<u32>,
) -> Ciphertext {
    // Plaintext: PRIVATE_ACCOUNT_KIND_HEADER_LEN-byte kind header || account serialization
    let mut buffer = kind.to_header_bytes().to_vec();
    buffer.extend_from_slice(&account.to_bytes());
    // Optional floor on the plaintext length, capped at MAX_CIPHERTEXT_PADDING
    if let Some(pad_to_len) = pad_to_len {
        assert!(pad_to_len <= MAX_CIPHERTEXT_PADDING);
        if pad_to_len as usize > buffer.len() {
            buffer.resize(pad_to_len as usize, 0);
        }
    }
    // Apply the ChaCha20 (RFC 8439) keystream: nonce [0; 12], block counter starting at 0
    let key = kdf(shared_secret, nullifier);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);
    Ciphertext(buffer)
}
```

`account.to_bytes()` is `borsh(account)`: the nonce (16 bytes LE), then the actor-state map (u32 LE entry count, then each `(program AccountId, u32 LE length, actor-state bytes)` entry in ascending key order). The encoding is length-prefixed, so trailing zero padding is ignored on decryption.

The circuit pads every note in a transaction to the same requested minimum length (`ciphertext_padding`), so a note's length does not reveal how much state the account holds. A fixed zero nonce is safe because every output has its own key (see [KDF](#kdf)).

#### Decryption

A receiver decrypts a note after recovering `ss` (see [Private account discovery](#private-account-discovery-with-viewing-keys)). `decrypt` returns `None` if the note is too short, its header is not a valid `PrivateAccountKind`, or the rest does not decode as an `Account`.

```rust
fn decrypt(
    ciphertext: &Ciphertext,
    shared_secret: &SharedSecretKey,
    nullifier: &Nullifier,
) -> Option<(PrivateAccountKind, Account)> {
    let mut buffer = ciphertext.0.clone();
    let key = kdf(shared_secret, nullifier);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);

    if buffer.len() < PRIVATE_ACCOUNT_KIND_HEADER_LEN {
        return None;
    }
    let header: &[u8; PRIVATE_ACCOUNT_KIND_HEADER_LEN] = buffer[..PRIVATE_ACCOUNT_KIND_HEADER_LEN].try_into().unwrap();
    let kind = PrivateAccountKind::from_header_bytes(header)?;
    // Reads one borsh Account from the front; any trailing padding is ignored.
    let account = Account::from_bytes(&buffer[PRIVATE_ACCOUNT_KIND_HEADER_LEN..]).ok()?;
    Some((kind, account))
}
```

The encryption has no authentication tag, so `decrypt` can succeed with the wrong key and return garbage. Integrity instead comes from the proof and from the receiver checking the decrypted account's commitment against the transaction's commitments (see [Private account discovery](#private-account-discovery-with-viewing-keys)).

## Programs

Programs define the logic for operating on actor states. They are stateless: a program runs once per message, on one actor, and can only change that actor's state. Apart from the initial state a host seeds at genesis, all changes to actor states, public or private, are performed through program execution. The exceptions are maintained by the protocol itself: the nonce (see [Nonce field](#nonce-field)) and the signing key state (see the key protocol).

A program is addressed by an `AccountId`, the address of its `ProgramHeader` (see [Program deployment](#program-deployment)). Its `ProgramId` is only the RISC Zero image ID of its bytecode, used to verify its receipts on the private path. The same bytecode deployed at two addresses is two distinct programs, each with its own actor states and PDAs.

Three reserved addresses have no guest ELF:

- `NATIVE_TOKEN_PROGRAM_ID` — the native token program, run as protocol code; the only writer of native balances.
- `PROGRAM_LOADER_ACCOUNT_ID` — the program loader, run as protocol code; the only writer of loader states. It is public-only.
- The signature program's address — it holds signing key states but has no code; a message to it fails as an unknown program.

### Actors and messages

A program is invoked by delivering a message to one of its actors. It receives the message together with the actor's current state and the grants the delivery carries (see [Authorization](#authorization)), and responds with the actor's new state and any messages it sends:

```rust
struct ReceiveInput {
    /// The actor processing the message.
    receiver: Actor,
    /// The actor that sent the message, at the address it presented;
    /// `None` when the transaction itself submitted it.
    from: Option<Actor>,
    /// The actors whose grants the receiver holds and may attach to its sync messages.
    grants: BTreeSet<Actor>,
    /// The receiver's actor state before handling the message.
    pre_state: ActorState,
    message: MessageData,
}

struct Response {
    /// `None` keeps the actor state; `Some(data)` replaces it (empty data removes it).
    post_state: Option<ActorState>,
    sync_messages: List<SyncMessage>,
    async_messages: List<AsyncMessage>,
    /// Dropped on the private path.
    events: List<ProgramEvent>,
    validity: ValidityWindows,
}

struct Transition {
    /// Must equal the ReceiveInput the program was given.
    input: ReceiveInput,
    response: Response,
}
```

A program sends two kinds of message:

- A **sync message** is delivered in the same transaction, before the sender's later siblings (see [Message processing](#message-processing)). It may carry grants the sender holds and PDA seeds of the sender's program.
- An **async message** is processed in a later transaction: it is published and later received by its destination (see [Messages](#messages)). It carries no grants. It runs on whatever program is deployed at its destination when it is received.

```rust
struct SyncMessage {
    to: Actor,
    message: MessageData,
    /// For each seed, the destination is authorized if it is the sender program's PDA for that seed.
    pda_seeds: BTreeSet<PdaSeed>,
    /// Grants the sender attaches, each over an actor whose grant it holds.
    grants: BTreeSet<Actor>,
}

struct AsyncMessage {
    to: Actor,
    message: MessageData,
}

/// A message with its sender, as delivered or published.
struct MessageBody {
    from: Actor,
    to: Actor,
    message: MessageData,
}

/// A program's reply carrying an actor state, e.g. to a read request.
struct StateReply {
    state: ActorState,
}

struct ProgramEvent {
    /// By convention, the first 8 bytes of SHA256("<program>::<EventName>").
    selector: [u8; 8],
    data: List<u8>,
}
```

`is_authorized()` on an input is `grants.contains(receiver)`: whether the delivery carries a grant over the receiving actor itself.

**Guest I/O.** A guest reads one frame holding the borsh-encoded `ReceiveInput`, and commits one frame holding the borsh-encoded `Transition`, then exits with code 0. A frame is a `u32` little-endian length followed by that many bytes. A guest that panics, pauses or exits with a non-zero code fails the transaction.

### Validation of transitions

After each transition:

1. `transition.input` equals the `ReceiveInput` the program was given.
2. The transition's validity windows intersect those of every earlier transition in the transaction (see [Validity windows](#validity-windows)).
3. Each sync message attaches only grants its sender holds: every grant in `SyncMessage.grants` must be in the sender's `ReceiveInput.grants`. A private sender may name a grant it holds under any address of the granted account (its canonical ID or a blinded alias of it).

`post_state` always applies to the receiving actor, so a program cannot write any other actor's state.

The input echo (rule 1) binds a transition to the exact delivery that produced it: the same receiver, sender, grants, pre-state and message. On the private path, where transitions arrive as receipts, this stops a valid receipt from being reused for a different delivery.

Each delivery is also checked before it runs (see [Message processing](#message-processing)): its destination must be an actor the transaction can place, and the program loader may only be reached in a wholly public execution.

### Message processing

Public and private execution share one executor. A transaction delivers its entry messages, and each delivery may cause further deliveries.

**Entries.** A transaction's top-level message, its *root*, is one of:

- a **sync root** (`RootCall { to, message }`), sent by the transaction itself (`from` is `None`), carrying the transaction's root grants (see [Authorization](#authorization));
- an **async root**: a published async message the transaction receives (privacy-preserving transactions only), delivered with its original sender as `from` and no grants.

A privacy-preserving transaction may also carry **claims**, published messages its private accounts receive, and a **fee transfer**, the native transfer that pays its fee from a private payer. Entries run in the order claims, root, fee transfer; the fee transfer waits for the root's whole subtree. A public transaction has only a sync root.

**Order.** Deliveries are processed depth-first: when a transition completes, the messages it sent are delivered in the order it emitted them, and each one's subtree completes before the next starts.

**Placement.** Each delivery runs on the side its destination belongs to:

- An actor declared in the transaction's public context (`PublicExecutionContext.actors`, each marked `Signer` or `None`) runs publicly. Its account must also be *admitted*: it exists in public state, the transaction carries evidence for it, or the delivery's sender reaches it as its program's public PDA by one of the delivery's seeds.
- An actor whose account has a private witness runs privately. A private account may also be reached under a blinded alias the witness opens.
- Any other destination fails the transaction. An account may not be both declared public and privately witnessed.

The program loader may only be reached in a wholly public execution.

**Async messages.** Each async message a transition sends either is **promoted**, delivered in the same transaction after its sender's sync messages, or is **published** to the commitment set for its destination to receive later (see [Messages](#messages)):

- An async message to a declared public actor is always promoted.
- A privacy-preserving transaction may promote others by index: async messages are numbered in emission order, separately for private and public senders, and the transaction lists the indices to promote. Every listed index must be reached.
- A promoted message carries no grants or seeds.

**Mixed execution.** A privacy-preserving transaction may involve both private and public actors. Its private actors run inside the privacy-preserving circuit, and its public actors run at settlement. Each delivery that crosses between the two is recorded in the proof, so settlement can replay the public side against what the circuit executed (see [The privacy-preserving execution circuit](#the-privacy-preserving-execution-circuit)).

### Authorization

Authority is carried as **grants**. A grant is an actor: holding a grant over an actor is holding the authority to act for it. Each delivery carries a set of grants, which the receiver holds while handling it (`ReceiveInput.grants`). `is_authorized()` reports whether the receiver holds a grant over itself; it is information for the program, which decides what it permits. For example, the native token program refuses to debit an unauthorized sender.

A program needs no authorization to write its own actor state, on any account it is delivered to. As a result, any program can create or change its own actor state on any account, including accounts whose owner has never used it. An account's actor-state map is therefore not under its owner's control; each program is responsible only for the meaning of its own actor state.

**Root grants.** Only the transaction's own sync root carries grants from the transaction's signers:

- *Public signers* — each declared public actor marked `Signer` whose account signs the transaction. A `Signer` mark on an account that does not sign is refused.
- *Private signers* — for each private account whose witness holds its authorization key (`RegularKey::Authorized`), the account's actors for the programs listed in the witness's `signer_programs`. A private root receives them directly. A public root holds a private grant only as declared in `PublicExecutionContext.private_signers`, under the presented address, and the proof checks each against the witness's marks. Public transactions cannot declare private signers.

Claims, async roots and promoted messages carry no grants: they were written by someone other than the transaction's signers. The fee transfer carries a grant over the payer's native balance actor only.

**Passing grants.** A sync message carries exactly the grants its sender attaches (`SyncMessage.grants`), each of which the sender must hold (see [Validation of transitions](#validation-of-transitions)). A program cannot create a grant, and a grant reaches only the deliveries it is attached to: it does not flow back to the sender's caller or to the sender's other messages unless the receiver attaches it again.

**Seed grants.** A sync message may also carry PDA seeds (`SyncMessage.pda_seeds`). The delivery then grants its destination actor if the destination's account is the sending program's PDA for one of the seeds:

- a public account whose ID equals `for_public_pda(P, seed)`, where `P` is the sender's `program_account_id`;
- a private PDA whose witness is bound to `(P, seed)`.

The seed grant is over the destination actor only, not over the PDA's other actors. The transaction's root has no sending program, so it carries no seed grants.

**Private addresses.** A private sender does not reveal its account ID. It appears as `from` under a *presented* address, either its canonical ID or a blinded alias of it (see [Account ID](#account-id)), except when it replies to its own caller, which sees the address it reached, or calls another actor of its own account. A grant over a private account travels the same way: a grant over the sender's own account is named under the sender's `from` address, and a grant over another private account crossing to the public side is presented under its own address. A private receiver holds a grant over its own account under the account itself.

**PDA family binding.** The same `(program, seed)` pair derives different private PDAs for different `(Npk, vpk)`. Without a further rule, one seed could authorize several accounts. So across a whole transaction:

> Each `(program_account_id, seed)` pair may resolve to **at most one** account ID.

Each private PDA witness is bound to its `(program, seed)` when execution starts, and each seed grant (public or private) binds its pair when it is first used. A second, different account under the same pair aborts the transaction. A transaction also may not declare the public PDA of a pair that a private PDA witness is bound to.

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

It keeps each account's balance in the account's **native balance** actor state, the actor state keyed by `NATIVE_TOKEN_PROGRAM_ID`, as 16 bytes little-endian. A balance of 0 is always stored as an empty actor state, which removes the entry from the account. Any other encoding is rejected: an actor state whose length is neither 0 nor 16 bytes, and 16 zero bytes (`[0_u8; 16]`), since zero is always the empty actor state. Apart from the initial state a host seeds at genesis, only the native token program writes this actor state.

Each account's native balance is its own actor, `Actor::native_balance(account_id)`, and receives these messages:

```rust
enum Message {
    Transfer { to: AccountId, amount: Balance },
    Credit(Balance),
    ReadState,
}
```

- **`Transfer { to, amount }`:** the receiving actor must be authorized (it holds a grant over itself). Its balance is debited by `amount` with checked arithmetic, and it sends the async message `Credit(amount)` to `to`'s native balance. Only the sender must be authorized, so anyone can send native tokens to any account without the recipient's involvement.
- **`Credit(amount)`:** accepted only from another native balance actor (the sender's `program_account_id` is `NATIVE_TOKEN_PROGRAM_ID`), so only a `Transfer` can credit a balance. The balance is credited with checked arithmetic.
- **`ReadState`:** sends the sync message `StateReply { state }` back to the sender, carrying the balance actor state unchanged. The reply attaches the grant over the balance the sender lent, if any, so the reader can then act on it. A `ReadState` with no sender fails.

Insufficient balance, overflow, an undecodable message or a non-canonical balance fails the transaction.

The credit is an async message: it is promoted, and so applied in the same transaction, when the recipient is a declared public actor or the transaction promotes it; otherwise it is published and applied when the recipient receives it (see [Message processing](#message-processing)). Every transfer debits and credits the same amount, so the total supply is conserved: between a debit and its credit, the amount is held by the published message.

A program moves native tokens out of an account it controls by sending a `Transfer` to that account's native balance with the account's PDA seed in `pda_seeds` (`native_token::custody_transfer`). The seed grants the balance actor (see [Authorization](#authorization)).

### Validity windows

Programs can constrain when the transaction that runs them may be accepted:

```rust
/// A half-open interval [from, to) with optional bounds.
/// None means unbounded on that side.
struct ValidityWindow<T> {
    from: Option<T>,
    to: Option<T>,
}

type BlockValidityWindow = ValidityWindow<BlockId>;
type TimestampValidityWindow = ValidityWindow<Timestamp>;

struct ValidityWindows {
    blocks: BlockValidityWindow,
    timestamps: TimestampValidityWindow,
}
```

A transition that sets no window is unbounded on both sides. The executor intersects the windows of every transition, so a single program's window restricts the whole transaction. An empty intersection fails execution, and so does a window with `from ≥ to`, which is empty to begin with. At settlement the intersection is checked against the block's ID and timestamp; on the private path it is committed in the circuit output and checked the same way.

### Metering

Public execution runs under a cycle budget shared by every transition of the transaction: `DEFAULT_PUBLIC_CYCLE_BUDGET`, or a budget the host chain sets. Each guest session is limited to the remaining budget. The native token program consumes no cycles. The program loader, which runs as protocol code, is charged `LOADER_CYCLES_PER_BYTE` for each byte of its pre-state and of every actor state it reads.

```rust
const LOADER_CYCLES_PER_BYTE: Cycles = 1;
```

When executed with metering, the charged cycle count is:

- **Success:** the cycles all transitions used. A transaction that fails only because a durable async message reached an address without a recovery binding is charged the same way.
- **A session halts with a non-zero exit code:** the cycles used so far, including that session's.
- **Any other failure** (a panic, a pause, exceeding the budget (`OutOfGas`), or a failure outside a guest session such as a failed validation, an empty window intersection or a failed native transfer): the full budget.

## Messages

An async message that is not promoted (see [Message processing](#message-processing)) is **published**: its commitment is appended to the commitment set, and the publication is kept in state at the commitment's position. Its destination receives it in a later privacy-preserving transaction.

### Publication

```rust
enum Publication {
    /// The message in the clear.
    Clear(MessageBody),
    /// The message with its contents and metadata shielded.
    Sealed(SealedMessage),
}

struct SealedMessage {
    commitment: Commitment,
    note: EncryptedNote,
}
```

A publication's leaf in the commitment set is its message commitment (see [Commitment](#commitment)): `Commitment::for_message(body)` for a clear message, and the sealed commitment carried by a sealed one. A transaction's message leaves are appended after its account commitments.

Async messages published by public execution are always clear. Each async message published by private execution is published in the mode the prover chooses for it: clear, or sealed to its recipient.

A clear message's destination must have a recovery binding (see [Recovery bindings](#recovery-bindings)), already in state or introduced by the same transaction. Otherwise the transaction fails; its cycles are charged as on success (see [Metering](#metering)).

### Recipients

Sealing and recovery both encrypt to a private recipient, described by its keys, its kind and, when it is reached under a blinded alias, the alias's opening:

```rust
struct Recipient {
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    kind: PrivateAccountKind,
    /// The blinding factor of the alias the recipient is reached under, if any.
    opening: Option<[u8; 32]>,
}

struct RecipientEncryption {
    recipient: Recipient,
    esk: EphemeralSecretKey,
}
```

The recipient's *address* is its account ID (`AccountId::for_private_account(npk, vpk, kind)`), or that ID blinded with `opening` when one is set. Encryption uses ML-KEM-768 deterministic encapsulation to `vpk` under `esk`, as for account notes (see [Key agreement and shared secret](#key-agreement-and-shared-secret)), giving a shared secret `ss` and the `epk` published in the note.

### Sealed messages

A sealed message hides its body from everyone but its sender and recipient. From the shared secret, the sender derives the hiding randomness `rho`, commits to the body under it, and encrypts the body under a key bound to that commitment:

$$\mathsf{rho} = \mathsf{SHA256}(\text{"LEE/v0.3/KDF-SHA256/Rho/"} \;||\; \mathsf{ss})$$

$$\mathsf{commitment} = \mathsf{SHA256}(\mathsf{SEALED\_COMMITMENT\_PREFIX} \;||\; \mathsf{SHA256}(\mathsf{borsh}(\mathsf{body})) \;||\; \mathsf{rho})$$

$$\mathsf{key} = \mathsf{SHA256}(\text{"LEE/v0.3/KDF-SHA256/Message/"} \;||\; \mathsf{ss} \;||\; \mathsf{commitment})$$

The prefixes are ASCII and not padded (24 and 28 bytes). The plaintext is a fixed-width header followed by the body:

```
kind header (PRIVATE_ACCOUNT_KIND_HEADER_LEN bytes) || opening flag (1 byte: 0 or 1) || opening (32 bytes, zero if absent) || borsh(body)
```

It is padded to the transaction's requested note length like an account note, and encrypted with the ChaCha20 keystream under `key` and a zero nonce. The header has the same width whatever the destination's kind or alias, so neither shows in the ciphertext's length.

The seal must address the message's destination: the recipient's address must equal `body.to.account_id`. A recipient opens a sealed message by decapsulating `epk`, decrypting, and accepting it only if the recomputed sealed commitment matches and the recovered recipient's address equals `body.to.account_id`.

### Recovery bindings

A recovery binding lets the owner of a private address learn that the address is theirs, and how to receive messages sent to it, by decrypting a note with their viewing key:

```rust
struct RecoveryBinding {
    address: AccountId,
    note: EncryptedNote,
}
```

The note's plaintext is `borsh((npk, kind, opening))`, zero-padded to 130 bytes (32 + `PRIVATE_ACCOUNT_KIND_HEADER_LEN` + 1 + 32), and is encrypted like an account note (see [Encryption](#encryption)) under the key

$$\mathsf{key} = \mathsf{SHA256}(\text{"LEE/v0.3/KDF-SHA256/Recovery/"} \;||\; \mathsf{ss} \;||\; \mathsf{address})$$

where the 29-byte prefix is ASCII and not padded. A recipient accepts a binding only if the recovered `(npk, kind, opening)` gives back its `address`.

Recovery bindings are introduced by privacy-preserving transactions and at genesis. Each address is bound at most once: a binding for an address already bound, in state or earlier in the same transaction, fails the transaction.

### Receiving messages

A private account receives a published message in a privacy-preserving transaction, either as a **claim** or as the transaction's **async root**. The prover supplies the message and the evidence that it was published:

```rust
struct MessageWitness {
    body: MessageBody,
    /// The hiding randomness of a sealed message; `None` for a clear one.
    rho: Option<[u8; 32]>,
    /// The message leaf's position and the path to it.
    membership_proof: MembershipProof,
    /// A dummy output, so spending a message looks like a state change.
    filler: DummyOutput,
}
```

The circuit recomputes the message's commitment from `body` (and `rho`, for a sealed message), checks the membership proof against a known commitment-set root, and finds the private witness the message is addressed to: the one whose account ID, or an alias it opens, equals `body.to.account_id`. It reveals the message nullifier for that account's `nsk` (see [Nullifier](#nullifier)), so each published message is received at most once. The message is then delivered to its destination with `from = body.from` and no grants.

## LEE v0.3 state

```rust
struct V03State {
    public_state: Map<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
    publications: Map<CommitmentPosition, Publication>,
    recovery_bindings: Map<AccountId, EncryptedNote>,
}
```

- `public_state`: A map from each account ID to its `Account`. The entire `AccountId` space is conceptually populated; account IDs not explicitly stored are treated as `Account::default()` (sparse representation). Deployed programs live here too, as loader states.
- `private_state`:
  - `CommitmentSet`: An authenticated Merkle tree of all private account commitments and published message commitments.
  - `NullifierSet`: The set of all revealed nullifiers.
- `publications`: Each published async message, keyed by the position of its leaf in the commitment tree (see [Messages](#messages)).
- `recovery_bindings`: Each recovery binding's note, keyed by its address (see [Recovery bindings](#recovery-bindings)).

Operations on the commitment set:
- `append(commitments, messages)` — append a transaction's account commitments, then its message commitments, and record the new root in `root_history`. The root is recorded once per batch, that is once per transaction, not once per leaf.
- `get_proof_for(commitment)` — Merkle inclusion path of an account commitment. A message leaf is found by its position alone, since the same message may be published at several positions.
- `compute_digest_for_path(commitment, proof)` — the root that a membership proof resolves to.
- `root_history.contains(digest)` — whether a digest was ever a root.

Which containers hold these maps and sets is an implementation choice and not part of the protocol; only membership and the commitment tree's root matter. The node uses persistent collections so that cloning a state shares structure.

### Commitment tree

The commitment set is an append-only binary Merkle tree over SHA-256. Leaves are inserted left to right; a leaf's index is its insertion position.

- A leaf is `SHA256(commitment)`; an internal node is `SHA256(left || right)`.
- Empty positions hold default values: the empty leaf is `[0; 32]`, and each level's default is the hash of two defaults from the level below.
- With *n* leaves, the root is that of the smallest power-of-two subtree holding all of them, of depth ⌈log₂ n⌉. The depth, and so the proof length, grows with the set; a single leaf's root is its leaf hash.
- A membership proof is `(index, siblings)`, from the leaf up to the root. To verify it, start from the leaf hash and, for each sibling, hash `(current, sibling)` if the index's low bit is 0 or `(sibling, current)` if it is 1, then shift the index right by one. The result must be in `root_history`.

### Dummy commitment and dummy commitment hash

Two special constants are derived from the default account and the null account ID `[0; 32]`:

```rust
/// DUMMY_COMMITMENT = Commitment::new(AccountId([0; 32]), &Account::default())
/// Concretely: SHA256(COMMITMENT_PREFIX || [0]*32 || SHA256([0]*20)),
/// where [0]*20 is borsh(Account::default()): a zero u128 nonce and an empty actor-state map (u32 length 0).
const DUMMY_COMMITMENT: Commitment = Commitment([
    59, 125, 5, 88, 44, 25, 75, 87, 238, 148, 130, 173, 76, 217, 13, 136, 125, 198, 106, 114, 48,
    245, 101, 6, 37, 70, 51, 208, 20, 5, 51, 18,
]);

/// DUMMY_COMMITMENT_HASH = SHA256(DUMMY_COMMITMENT)
const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    107, 9, 131, 34, 17, 0, 16, 21, 11, 42, 160, 50, 189, 133, 209, 183, 60, 242, 84, 238, 254, 37,
    123, 26, 90, 172, 192, 13, 95, 233, 84, 41,
];
```

`DUMMY_COMMITMENT` is the commitment of the default account (`Account::default()`) under the null account ID (`[0; 32]`). It is not a real user account: no keys exist that could spend it, so it can never be nullified. It is unrelated to the dummy actions of the privacy-preserving circuit (see [Dummy actions](#dummy-actions)).

At genesis, the `CommitmentSet` is initialized by inserting `DUMMY_COMMITMENT` as its first entry. This bootstraps the Merkle tree before any real private accounts exist and gives the set a well-defined root from the very first state. Because the Merkle tree hashes each leaf as `SHA256(value)`, the root of a tree containing only `DUMMY_COMMITMENT` is `SHA256(DUMMY_COMMITMENT)` — which is exactly `DUMMY_COMMITMENT_HASH`. As a result, `DUMMY_COMMITMENT_HASH` is permanently present in the `CommitmentSet`'s `root_history` from genesis onward.

**Role in initialization nullifiers.** Every nullifier submitted in a `PrivacyPreservingTransaction` must be paired with a `CommitmentSetDigest`. For update nullifiers this is the Merkle root that the sender's membership proof resolves to. For **initialization nullifiers** — revealed when a private account is created (`NullifierWitness::Init`, for both regular accounts and PDAs) — the spent commitment is that of the default account, which is never in the tree, so there is no natural Merkle root to cite; the prover supplies one (`commitment_root`). Rather than special-casing this in acceptance, initialization nullifiers go through the same `root_history.contains(digest)` check as other nullifiers, so any known root is accepted. `DUMMY_COMMITMENT_HASH` is always in `root_history` and therefore always valid, but wallets should cite the same current root they use for their other nullifiers: a transaction whose initialization nullifiers all cite `DUMMY_COMMITMENT_HASH` reveals which of its actions create new accounts. Dummy actions carry a prover-chosen root in the same way.

### Genesis

Genesis state starts as `V03State::default()`: an empty public state and a `CommitmentSet` holding only `DUMMY_COMMITMENT`. The host chain then adds its initial state directly, without running any program:

- **Public accounts**, written as given (for example, pre-funded balances).
- **Recovery bindings**, stored as given, so that genesis can address messages to private accounts (for example, pending credits to pre-funded private accounts).
- **Programs**, each stored exactly as a live deploy would leave it:
  - its `user_elf` is split into chunks of at most `MAX_SEGMENT_DATA_LEN` bytes, stored as `ProgramSegment`s at the genesis segment addresses (see [Account ID](#account-id));
  - a `ProgramHeader` pointing at the first segment is stored at the address the host chooses (LEZ seeds its system programs at `from_system_program_name(name)`, which is fixed regardless of the ELF);
  - if the program is seeded as immutable, its mirror commitment is appended to the `CommitmentSet`.

## Program deployment

Programs are stored as data in public accounts, in the loader state (the actor state keyed by `PROGRAM_LOADER_ACCOUNT_ID`), which only the program loader writes. A loader state holds a borsh-encoded `LoaderEntry`, either a `ProgramHeader` or a `ProgramSegment`; the tag keeps one from decoding as the other:

```rust
enum LoaderEntry {
    Header(ProgramHeader),
    Segment(ProgramSegment),
}

/// Stored at the program's address.
struct ProgramHeader {
    /// The image ID of the segment chain plus the protocol kernel, computed at deploy/update time.
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

**Resolution.** To run the program at address `P`, decode `P`'s loader state as a `ProgramHeader` (none, or undecodable, means *unknown program*). Starting at `program_first_segment`, follow `next_segment` links, concatenating each segment's `bytecode`, for at most `MAX_PROGRAM_SEGMENTS` segments; a missing or undecodable segment, or a longer chain, also means *unknown program*. The result is the user ELF; it is combined with the protocol's fixed kernel (`risc0_zkos_v1compat`) to form the executable binary. The header's stored `image_id` is used as the program's ID without being recomputed at dispatch. It is trustworthy because the loader computes it when writing the header and never accepts it from the caller. This relies on headers being written only by the loader or at genesis.

**Program loader messages.** The loader is reached by a message to a target account's loader actor, `(target, PROGRAM_LOADER_ACCOUNT_ID)`, and only in a wholly public execution. It reads the loader state of any other account it needs directly, including loader states written earlier in the same transaction, so a single transaction can deploy a program and then call it. No message may target `NATIVE_TOKEN_PROGRAM_ID` or `PROGRAM_LOADER_ACCOUNT_ID`.

```rust
enum Message {
    WriteSegment { bytecode: List<u8>, next_segment: Option<AccountId> },
    CreateHeader { first_segment: AccountId, immutable: bool },
    UpdateHeader { first_segment: AccountId, immutable: bool },
    CreateHeaderOf { first_segment: AccountId, image_id: ProgramId, immutable: bool },
    AssertMutable,
}
```

- **`WriteSegment`** — the target's loader state must be empty and the target must be **authorized**. If `next_segment` is `Some`, that account must already hold a valid segment, so chains are written from the tail to the head. The segment's size is not checked; deployers split bytecode into segments of `MAX_SEGMENT_DATA_LEN` bytes.
- **`CreateHeader`** — the target's loader state must be empty and the target must be **authorized**. The loader follows the chain from `first_segment` (at most `MAX_PROGRAM_SEGMENTS` segments, each a valid segment) and computes the header's `image_id` from the concatenated bytecode plus the kernel. It is never taken from the caller.
- **`UpdateHeader`** — as `CreateHeader`, but the target must already hold a header with `immutable == false`.
- **`CreateHeaderOf`** — as `CreateHeader`, but fails unless the computed `image_id` equals the given one.
- **`AssertMutable`** — fails unless the target holds a header with `immutable == false`. It changes nothing.

Segments are write-once: they can never be changed or deleted. `UpdateHeader` only repoints the header to a new chain; the old segments stay in place.

When a header is written with `immutable == true`, the transaction also appends the header's **mirror commitment** to the `CommitmentSet`:

```rust
fn immutable_mirror_commitment(header_account_id: AccountId, header: &ProgramHeader) -> Commitment {
    let mirror = Account::default().with_actor_state(PROGRAM_LOADER_ACCOUNT_ID, borsh(header));
    Commitment::new(AccountId::for_immutable_mirror(header_account_id), &mirror)
}
```

The mirror holds the header untagged (`borsh(header)`, not a `LoaderEntry`). A private transaction can later prove membership of this commitment to show that it ran *some* immutable deployed program without disclosing which one.

**Shadow programs.** A program can also run on the private path without being deployed. Its address is [`for_shadow_program(image_id)`](#account-id), derived from its image ID alone, so the address itself authenticates the bytecode. A shadow address has no header and no key, so public dispatch cannot resolve it and nobody can deploy a program at the shadow address (every loader write requires an authorization).

## Built-in programs

Built-in programs are part of the node rather than deployed by users. There are two kinds.

**Native built-ins.** LEE implements two programs as protocol code rather than as guest ELFs: the native token program (see [Native token program](#native-token-program)) and the program loader (see [Program deployment](#program-deployment)). Their addresses are reserved: no bytecode can be deployed there, and a privacy-preserving transaction cannot claim a guest image for them. The loader is public-only.

**Genesis-seeded built-ins.** A host chain built on LEE, such as each LEZ zone, can add more built-in programs. These are ordinary guest programs seeded at genesis (see [Genesis](#genesis)), either as immutable programs or as system programs at their name-derived addresses (`from_system_program_name`), which the system upgrader can later upgrade. Which programs are seeded is up to the host; LEZ's set is documented in `lez-specs.md`. Additional user-defined programs may also be deployed with the program loader (see [Program deployment](#program-deployment)).

## Structure of a public transaction

```rust
/// Shared by public and privacy-preserving transactions; `P` is the kind-specific execution.
struct TransactionMessage<P> {
    public_context: PublicExecutionContext,
    execution: P,
    /// One nonce per signer, keyed by the signer's account.
    nonces: BTreeMap<AccountId, Nonce>,
    /// None for a fee-exempt transaction.
    fee: Option<FeeDeclaration>,
    /// Evidence that accounts not yet in state are public accounts.
    admission_evidence: List<PublicAccountEvidence>,
}

struct PublicExecutionContext {
    /// The declared public actors, each marked Signer or None.
    actors: BTreeMap<Actor, Authority>,
    /// The accounts whose signatures authorize the transaction.
    authorized_accounts: BTreeSet<AccountId>,
    /// Indices of async messages to promote (privacy-preserving transactions only).
    promotions: BTreeSet<u64>,
    /// Presented private actors whose grants a public root holds (privacy-preserving transactions only).
    private_signers: BTreeSet<Actor>,
}

enum Authority { None, Signer }

enum PublicAccountEvidence {
    /// The account's initial key: the account is `AccountId::for_initial_key(key)`.
    Key(SigningKeyState),
    /// The account is `AccountId::for_public_pda(program, seed)`.
    Pda { program: AccountId, seed: PdaSeed },
}

struct PublicExecution {
    root: RootCall,
}

struct RootCall {
    to: Actor,
    message: MessageData,
}

type Message = TransactionMessage<PublicExecution>;

struct FeeDeclaration {
    /// The account debited for the fee; must sign the transaction.
    payer: AccountId,
    gas_limit: Gas,
    tip: Fee,
    max_fee: Balance,
}

struct WitnessEntry {
    auth_data: List<u8>,
    next: SigningKeyState,
}

struct WitnessSet {
    entries: List<WitnessEntry>,
}

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

The message hash is `SHA256(PREFIX || borsh_serialize(message))`. Signers sign the message hash together with their next keys, under the keyed prefix `/LEE/v0.3/KeyedMessage/Public/` (see the key protocol).

### Message

- `public_context.actors`: the public actors the transaction declares. The root's destination must be declared. Each is marked `Signer` or `None`; a `Signer` actor whose account does not sign is refused, and an actor may be declared only once.
- `public_context.authorized_accounts`: must equal the signers, the accounts in `nonces`.
- `public_context.promotions` and `public_context.private_signers`: must be empty in a public transaction.
- `execution.root`: the transaction's sync root (see [Message processing](#message-processing)).
- `nonces`: one nonce per signer. Each must match the current nonce of the signer's account in state.
- `fee`: the signed fee declaration. It is covered by the message hash, so every signature authorizes it.
- `admission_evidence`: evidence that accounts not yet in public state are public accounts, so that they can be admitted (see [Message processing](#message-processing)): an account's initial key, or the program and seed of a public PDA.

### Witness set

One witness entry per signer, in the order of `nonces`. Each entry authenticates its signer against the account's current authorization key and commits it to its next key (see the key protocol). A signer's `Signer`-marked actors receive the root's grants (see [Authorization](#authorization)). Upon acceptance, each signer's nonce is incremented by 1 and its stored key becomes its `next`.

### Fees

LEE provides what a host chain needs to charge fees; the host (LEZ) sets the prices and settles the fee.

What LEE provides:

- **Fee declaration.** The message's `fee` field. `None` marks a fee-exempt transaction; `Some` marks a charged one.
- **Payer check.** For a charged transaction, `is_fee_authorized` requires `fee.payer` to be a signer (in `nonces`); execution authenticates every signer.
- **Metered execution.** The transaction runs under a cycle budget and reports the cycles it used.
- **Fee-settlement invocations.** Each is a single program call that the host runs outside the transaction itself, to transfer fee funds: for example, from the payer into a fee account (the reserve) and back (the refund). Instead of checking signatures, the host supplies which accounts count as authorized. For the reserve that is the payer, whose signature on the fee declaration already approves the charge; for the refund, none. Fee-settlement invocations advance no nonces and rotate no keys.

How the host settles a charged transaction:

1. Reserve the fee from the payer (a fee-settlement invocation).
2. Execute the transaction under a cycle budget derived from `gas_limit`.
3. Refund the unused part to the payer (a second fee-settlement invocation).

## Structure of a privacy-preserving transaction

```rust
type Message = TransactionMessage<ProvenExecution>;

struct ProvenExecution {
    /// Deliveries crossing between private and public actors, in execution order
    /// (see The privacy-preserving execution circuit).
    boundary: Boundary,
    /// Async messages published by private execution, each clear or sealed.
    async_messages: List<Publication>,
    /// Recovery bindings introduced by the transaction.
    recovery_bindings: List<RecoveryBinding>,
    /// The sync root when it runs publicly; None for a private sync root or an async root.
    public_root: Option<RootCall>,
    private_actions: List<PrivateAction>,
    /// The intersection of every private transition's windows.
    validity: ValidityWindows,
    program_image_claims: List<ProgramImageClaim>,
    /// The fee transfer's refund target, tip and fallback, when a private payer pays the fee.
    proven_fee: Option<ProvenFee>,
}

struct PrivateAction {
    nullifier: Nullifier,
    root: CommitmentSetDigest,
    commitment: Commitment,
    encrypted_post_state: EncryptedNote,
}

enum ProgramImageClaim {
    /// The program at `account_id` has image `image_id`.
    Disclosed { account_id: AccountId, image_id: ProgramId },
    /// Some immutable header's mirror commitment is a member of the tree with this root.
    Undisclosed { root: CommitmentSetDigest },
}

struct ProvenFee {
    /// A public account the unspent part of the fee is returned to; None returns it to the payer.
    refund_to: Option<AccountId>,
    /// The part of the fee paid to the block producer.
    tip: Fee,
    /// What settlement applies instead of the private actions when the public part fails,
    /// if the payer's pre-state covers the fee on its own.
    fallback: Option<FeeFallback>,
}

struct FeeFallback {
    nullifier: Nullifier,
    root: CommitmentSetDigest,
    commitment: Commitment,
    /// The payer's post-state note, under the ephemeral key of the payer's private action.
    ciphertext: Ciphertext,
    boundary: Boundary,
}

struct WitnessSet {
    entries: List<WitnessEntry>,
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

The hash is `SHA256(PREFIX || borsh_serialize(message))`. Signers sign it together with their next keys, under the keyed prefix `/LEE/v0.3/KeyedMessage/Privacy/` (see the key protocol).

### Message

`public_context`, `nonces`, `fee` and `admission_evidence` are as for a public transaction (see [Message](#message)), except that `public_context` may also select promotions (`promotions`) and declare the private signers a public root holds (`private_signers`). The proof is checked against `public_context` and `execution`.

The execution is what the circuit proves (see [Circuit output](#circuit-output)):

1. `boundary`: the deliveries between private and public actors. The message carries no public post-states: settlement computes them by replaying the public part against this boundary on live state.
2. `async_messages` and `recovery_bindings`: what private execution publishes (see [Messages](#messages)).
3. `public_root`: the transaction's sync root when its destination is a declared public actor.
4. `private_actions`: one entry per private account plus any dummy actions. Each has a nullifier, the root it is checked against, a new commitment, and an encrypted note. Nullifiers and commitments are sorted **independently**, so an action's commitment is not necessarily the one its nullifier and note belong to.
5. `validity`: the intersection of the private transitions' windows; the public part's windows are intersected with it at settlement.
6. `program_image_claims`: one claim per program image witness in the circuit input: normally one for each deployed program whose receipts the proof verified (shadow programs need none).
7. `proven_fee`: present when a private payer pays the fee through the transaction's fee transfer. The fee may instead be declared by a public payer in `fee`; LEZ requires exactly one of the two.

### Witness set

- `entries`: one witness entry per public signer, as for public transactions (see [Witness set](#witness-set)).
- `proof`: a borsh-serialized `risc0_zkvm::InnerReceipt` proving correct execution of the privacy-preserving circuit.

## The privacy-preserving execution circuit

The circuit is a RISC-V program proven with the risc0 zkVM. The transaction sender executes it off-chain; settlement verifies the proof and replays the transaction's public part. The circuit runs the private part of the shared executor (see [Message processing](#message-processing)), with a backend that **verifies** each guest transition instead of executing it:

1. **Private transitions.** For each delivery to a private actor, take the next `Response` from the input, form `Transition { input, response }` from the executor's `ReceiveInput`, and `env::verify` its framed journal against the image ID of the receiving program. The native token program's transitions are recomputed in-circuit. The program loader cannot be reached.
2. **Public transitions** are not run in the circuit, which never reads public state. Deliveries crossing to and from public actors are recorded on the boundary instead (see [Mixed execution](#mixed-execution)).
3. **Outputs.** For each private witness, compute the nullifier, new nonce, commitment and encrypted note. Then add the actions of received messages and dummy inputs, publish the async messages, sort, and commit the output.

The image ID of a receiving program comes from the input:

- a `ProgramImageWitness::Disclosed { account_id, image_id }` becomes a `Disclosed` claim, which settlement checks against the header deployed at `account_id`;
- a `ProgramImageWitness::Undisclosed { account_id, program_header, membership_proof }` requires `program_header.immutable`, and becomes an `Undisclosed { root }` claim, where `root` is the digest the membership proof gives for the header's mirror commitment;
- a `ShadowProgramWitness { image_id }` maps `for_shadow_program(image_id)` to `image_id` and produces no claim.

An address may be claimed by at most one witness, and no image may be claimed for `NATIVE_TOKEN_PROGRAM_ID` or `PROGRAM_LOADER_ACCOUNT_ID`. Every supplied response and sender presentation must be consumed, and every listed promotion reached.

### Mixed execution

A transaction's private and public actors run in separate places, so the circuit and settlement each run one side and agree on the deliveries between them, recorded in order as the transaction's **boundary**:

```rust
/// A message with its sender and the authorization it carries.
struct Delivery<S> {
    envelope: MessageEnvelope<S>,
    grants: BTreeSet<Actor>,
    pda_seeds: BTreeSet<PdaSeed>,
}

enum BoundaryStep {
    PrivateToPublic(Delivery<Actor>),
    PublicToPrivate(Delivery<Actor>),
    EndPrivateSubtree,
    EndPublicSubtree,
}

type Boundary = List<BoundaryStep>;

/// For each public segment, in order, the deliveries its public actors make into private actors.
type PredictedCrossMessages = List<List<Delivery<Actor>>>;
```

**In the circuit.** A delivery from a private actor to a declared public actor is recorded as `PrivateToPublic` and opens a *public segment*; the circuit does not run it. A public root opens a segment in the same way. For each segment, in order, the prover supplies the deliveries its public actors will make into private actors (the *predicted cross messages*). The circuit delivers each one, recorded as `PublicToPrivate`: its sender must be a declared public actor and its destination private. Each such delivery's subtree is closed by `EndPrivateSubtree`, and the segment by `EndPublicSubtree`. Every supplied segment must be entered.

**At settlement.** The public part replays the boundary on live state. It runs the public root, if any, and delivers each `PrivateToPublic` step as recorded. Each delivery the public side makes to a private actor must equal the next `PublicToPrivate` step, including its grants, which are the grants the public sender actually held. The end markers must match, and the boundary must be consumed exactly. A mismatch fails the transaction.

The prover obtains the predicted cross messages by simulating the whole transaction against current state.

### Circuit input

```rust
struct PrivacyPreservingCircuitInput {
    input: ProvingInput,
    program_image_witnesses: List<ProgramImageWitness>,
    shadow_program_witnesses: List<ShadowProgramWitness>,
    /// One per guest transition of a private actor, in execution order.
    responses: List<Response>,
    /// One per private sender's presented address, in execution order.
    sender_presentations: List<SenderPresentation>,
    /// One per async message published by private execution, in the order it publishes them.
    publication_modes: List<PublicationMode>,
    predicted_cross_messages: PredictedCrossMessages,
}

struct ProvingInput {
    root: TransactionEntry<MessageWitness>,
    /// Received messages, delivered before the root, in order.
    claims: List<MessageWitness>,
    /// The native transfer that pays the fee from a private payer, run after the root.
    fee: Option<FeeTransfer>,
    public_context: PublicExecutionContext,
    /// One witness per private account used by the transaction.
    private_witnesses: List<PrivateWitness>,
    dummy_inputs: List<DummyInput>,
    /// Minimum plaintext length of each note, at most MAX_CIPHERTEXT_PADDING.
    ciphertext_padding: Option<u32>,
    /// Recipients of the recovery bindings the transaction introduces.
    recoveries: List<RecipientEncryption>,
    /// Indices of async messages from private senders to promote.
    private_promotions: BTreeSet<u64>,
}

enum TransactionEntry<R> {
    Sync(RootCall),
    Async(R),
}

struct FeeTransfer {
    payer: AccountId,
    recipient: AccountId,
    amount: Balance,
    refund_to: Option<AccountId>,
    tip: Fee,
}

struct PrivateWitness {
    vpk: ViewingPublicKey,
    /// Entropy for the note's ephemeral secret key.
    random_seed: [u8; 32],
    kind: WitnessKind,
    nullifier: NullifierWitness,
    /// Blinding factors of the aliases the account may be reached or presented under.
    address_openings: BTreeSet<[u8; 32]>,
    /// Programs whose actor on this account an authorized witness grants at the root.
    signer_programs: BTreeSet<AccountId>,
}

enum WitnessKind {
    Regular(RegularKey),
    /// Private PDA of program `binding.0` under seed `binding.1`.
    Pda { nsk: NullifierSecretKey, binding: (AccountId, PdaSeed) },
}

enum RegularKey {
    Authorized(AuthorizationSecretKey),
    Nullifying(NullifierSecretKey),
    FeeOnly(AuthorizationSecretKey),
}

enum NullifierWitness {
    /// New account: the pre-state is Account::default().
    Init { commitment_root: CommitmentSetDigest },
    /// Existing account, spent with a membership proof.
    Update { account: Account, membership_proof: MembershipProof },
}

enum SenderPresentation {
    Canonical,
    Blinded([u8; 32]),
}

enum PublicationMode {
    Clear,
    Sealed(RecipientEncryption),
}

struct DummyInput {
    nullifier_seed: [u8; 32],
    commitment_root: CommitmentSetDigest,
    output: DummyOutput,
}

/// The output of an action that creates no account state.
struct DummyOutput {
    commitment_seed: [u8; 32],
    note: EncryptedNote,
}

enum ProgramImageWitness {
    Disclosed { account_id: AccountId, image_id: ProgramId },
    Undisclosed { account_id: AccountId, program_header: ProgramHeader, membership_proof: MembershipProof },
}

struct ShadowProgramWitness {
    image_id: ProgramId,
}
```

`MessageWitness` is defined in [Receiving messages](#receiving-messages).

Checks when execution starts:

- Each witness's account ID (below) is unique among witnesses, and no witnessed account is also declared public. Each alias a witness opens names only its account and collides with no declared account.
- Each `Pda` witness binds its `(program, seed)` family (see [Authorization](#authorization)).
- Each private signer declared in `public_context.private_signers` is an actor an `Authorized` witness marks in `signer_programs`.
- The fee payer, if any, is a witnessed account whose witness holds its authorization key (`Authorized` or `FeeOnly`).

### Circuit output

```rust
struct PrivacyPreservingCircuitOutput {
    public_context: PublicExecutionContext,
    execution: ProvenExecution,
}
```

`ProvenExecution` is the transaction message's `execution` (see [Structure of a privacy-preserving transaction](#structure-of-a-privacy-preserving-transaction)). The journal is `to_borsh_frame(output)`.

### Circuit logic summary

For each private witness, `nsk` is the witness's own (`Nullifying`, `Pda`) or `nsk(ask)` (`Authorized`, `FeeOnly`), and `Npk = Npk(nsk)`:

| Witness | Account ID | Pre-state | New nonce | Nullifier, root | Authorized |
|---|---|---|---|---|---|
| `Regular`, `Init` | `for_regular_private_account(Npk, vpk)` | default | `nonce_increment(0, nsk)` | initialization nullifier, `commitment_root` | per key |
| `Regular`, `Update` | same | `account` | `nonce_increment(account.nonce, nsk)` | account nullifier of `Commitment::new(id, account)`, root from membership proof | per key |
| `Pda`, `Init` | `for_private_pda(program, seed, Npk, vpk)` | default | `nonce_increment(0, nsk)` | initialization nullifier, `commitment_root` | only via seed grants |
| `Pda`, `Update` | same | `account` | `nonce_increment(account.nonce, nsk)` | account nullifier, root from membership proof | only via seed grants |

"Per key": an `Authorized` witness grants the actors in `signer_programs` at the root, a `FeeOnly` witness authorizes only the fee transfer, and a `Nullifying` witness authorizes nothing.

The account's post-state is `Account { nonce: new_nonce, data: actor states after execution }`. Its action is:

- `commitment = Commitment::new(account_id, post_state)`;
- `esk = EphemeralSecretKey::new(account_id, random_seed, new_nonce)`, then `(ss, epk) = encapsulate_deterministic(vpk, esk)`;
- `ciphertext = encrypt(post_state, kind, ss, nullifier, ciphertext_padding)`, where `kind` is `Regular` or `Pda { account_id: program, seed }`.

When the fee payer is private, the circuit also computes its fee fallback: the payer's pre-state less the fee, under the same nonce and shared secret, encrypted with the fallback key (see [KDF](#kdf)), with a boundary carrying only the fee's crossing. A recovery binding whose `esk` and `vpk` match a witness's note reuses that note's encapsulation.

Each received message (claim or async root) adds one action: its message nullifier and root, with a dummy commitment and note from its `filler`. Each dummy input adds one dummy action (see [Dummy actions](#dummy-actions)).

Finally the actions are sorted by nullifier, and the list of commitments is sorted separately and reassigned in that order. This hides which commitment belongs to which nullifier and which actions are dummies.

### Dummy actions

A privacy-preserving transaction may include *dummy actions*: private actions that correspond to no account. They hide how many real private accounts the transaction touches, and on chain they are indistinguishable from real actions. A received message's action is built the same way, so receiving a message looks like a state change.

The prover supplies one `DummyInput` per dummy action (see [Circuit input](#circuit-input)). For each, the circuit emits a private action whose nullifier and commitment are derived from the input's seeds:

```rust
/// ASCII "/LEE/v0.3/Nullifier/Dummy/" zero-padded to 32 bytes
DUMMY_NULLIFIER_PREFIX: [u8; 32] = b"/LEE/v0.3/Nullifier/Dummy/\x00\x00\x00\x00\x00\x00"
/// ASCII "/LEE/v0.3/Commitment/Dummy/" zero-padded to 32 bytes
DUMMY_COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/Dummy/\x00\x00\x00\x00\x00"

impl Nullifier {
    /// 64-byte preimage.
    fn for_dummy(nullifier_seed: &[u8; 32]) -> Self {
        let mut bytes = DUMMY_NULLIFIER_PREFIX.to_vec();
        bytes.extend_from_slice(nullifier_seed);
        sha256(bytes)
    }
}

impl Commitment {
    /// 96-byte preimage.
    fn for_dummy(nullifier: &Nullifier, commitment_seed: &[u8; 32]) -> Self {
        let mut bytes = DUMMY_COMMITMENT_PREFIX.to_vec();
        bytes.extend_from_slice(&nullifier.to_byte_array());
        bytes.extend_from_slice(commitment_seed);
        sha256(bytes)
    }
}
```

A received message's action uses its message nullifier in place of `for_dummy(nullifier_seed)`, and its `filler`'s seed for the commitment.

The action's root is the input's `commitment_root`, which, like any action's, must be a known root. Its note is the output's `EncryptedNote`, used as given: its ciphertext must be at least `ciphertext_padding` bytes long, and its `epk` exactly `ML_KEM_768_CIPHERTEXT_LEN` bytes.

On chain, a dummy action's nullifier and commitment are added to the nullifier and commitment sets like any others. The commitment belongs to no account and no key, so it can never be spent.

The prover is responsible for making dummy actions indistinguishable from real ones: seeds must be random, and notes must look like real notes. ML-KEM ciphertexts are not uniformly random bytes, so a dummy note's `epk` should come from a real encapsulation.

Dummy actions are unrelated to `DUMMY_COMMITMENT`, the fixed first entry of the commitment set (see [Dummy commitment and dummy commitment hash](#dummy-commitment-and-dummy-commitment-hash)).

## Encrypted private account discovery and tagging

### View tags

Each private action includes a 1-byte view tag, so wallets can filter actions before attempting decapsulation:

$$\mathsf{ViewTag} = \mathsf{SHA256}(\text{"/LEE/v0.3/ViewTag/"} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk})[0]$$

where `Npk` is the 32-byte nullifier public key and `vpk` is the `VIEWING_PUBLIC_KEY_LEN`-byte viewing public key of the recipient; the 18-byte prefix is not padded. On average only 1 in 256 actions passes this filter for a given account. The tag depends only on the recipient's keys, so every note to the same `(Npk, vpk)` carries the same tag: it trades one byte of linkability for faster scanning, and anyone who knows a recipient's public keys can compute their tag. For an update, the circuit copies the tag from the witness rather than recomputing it, so the prover must supply the account's correct tag.

### Private account discovery with viewing keys

For each private action of a transaction:

1. Compute the expected view tag from the wallet's `(Npk, vpk)`. Skip the action if it does not match.
2. Decapsulate `epk` with the viewing secret key `(d, z)` to get `ss`. Skip on failure.
3. Decrypt the ciphertext with `(ss, action.nullifier)`.
4. Parse the `PRIVATE_ACCOUNT_KIND_HEADER_LEN`-byte header to recover `PrivateAccountKind`, and the rest to recover the `Account`.
5. Rebuild the account ID from the kind and the wallet's `(Npk, vpk)`.
6. Recommended: check that `Commitment::new(account_id, account)` is one of the transaction's commitments. Because commitments are shuffled, check membership in the whole list, not the entry at the same position.

```rust
fn private_account_discovery(
    tx: &PrivacyPreservingTransaction,
    vsk: &ViewingSecretKey, // (d, z)
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
) -> List<(PrivateAccountKind, Account)> {
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
    let pairs = tx.witness_set.signatures_and_public_keys;
    assert_eq!(message.nonces.len(), pairs.len());
    let signers = pairs.map(|(_, pk)| AccountId::from(pk));
    assert_no_duplicates(signers);
    for (signature, public_key) in pairs {
        assert!(signature.is_valid_for(message.hash(), public_key));
    }
    for (signer, nonce) in signers.zip(message.nonces) {
        assert_eq!(state.get_account(signer).nonce, nonce);
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
- **Signatures and nonces:** The same rules as for public transactions: counts match, no duplicate signers, valid signatures, and matching nonces.
- **Validity windows:** The current `block_id` and `timestamp` fall within the message's windows.
- **Program image claims:** For each `Disclosed { account_id, .. }` claim, a program is deployed at `account_id`; the claim is rebuilt with that header's `image_id`, not the one in the message. For each `Undisclosed { root }` claim, `root` is in `root_history`.
- **Proof verification:** The proof verifies against `PRIVACY_PRESERVING_CIRCUIT_ID` and the circuit output rebuilt from the message. In that output, each public action's `is_authorized` is recomputed as "the account is a signer", and the claims are the rebuilt ones.
- **Commitment freshness:** No new commitment is already in the `CommitmentSet`.
- **Nullifier validity:** No nullifier is already in the `NullifierSet`, and each action's `root` (the commitment-set root it was proven against) is in the `CommitmentSet`'s `root_history`.
- **Settlement:** The deferred public effects apply cleanly. For each public action, in order, each effect is applied to the account's current shard by the program resolved at the effect's `program_account_id` (the native token program is recomputed), under one shared `DEFAULT_PUBLIC_CYCLE_BUDGET`. Each apply output must pass `validate_apply_output`.

Privacy-preserving transactions are not metered or charged: any failure, including a failed settlement, rejects the transaction and leaves the state unchanged.

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
    for (sig, pk) in witness_set.signatures_and_public_keys {
        assert!(sig.is_valid_for(message.hash(), pk));
    }
    for (signer, nonce) in signers.zip(message.nonces) {
        assert_eq!(state.get_account(signer).nonce, nonce);
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
fn apply_state_diff(state: &mut V03State, diff: StateDiff) -> List<TransactionEvent> {
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

Validation happens entirely before this step, so a rejected transaction changes nothing. When a host executes with metering (see [Public transaction acceptance criteria](#public-transaction-acceptance-criteria)), a charged failure yields a diff containing only the signers' nonce increments.

Programs are deployed by ordinary public transactions to the program loader (see [Program deployment](#program-deployment)); there is no separate deployment transaction.
