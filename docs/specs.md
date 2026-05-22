# LEZ v0.3 specifications

## LEZ v0.3 basic types and constants

```rust
type AccountId = [u8; 32];
type NativeToken = u128;
type ProgramId = [u32; 8];
struct PdaSeed([u8; 32]);
type Data = List<u8>;
type Nonce = u128;
type ByteString = List<u8>;
type InstructionData = List<u32>;

/// Sequencer-supplied block height and timestamp.
type BlockId = u64;
/// Unix timestamp in milliseconds.
type Timestamp = u64;

/// Diversifies private accounts for a given NPK.
/// A single (nsk, vpk) keypair controls up to 2^128 distinct private accounts,
/// one per identifier value.
type Identifier = u128;

type Commitment = [u8; 32];
struct CommitmentSet {
    merkle_tree: MerkleTree,
    commitments: HashMap<Commitment, usize>,
    root_history: HashSet<CommitmentSetDigest>,
}
type CommitmentSetDigest = [u8; 32];
type MembershipProof = (usize, List<[u8; 32]>);

type Nullifier = [u8; 32];
type NullifierSecretKey = [u8; 32];
type NullifierPublicKey = [u8; 32];
type NullifierSet = BTreeSet<Nullifier>;

/// A secp256k1 scalar (32 bytes).
type EphemeralSecretKey = [u8; 32];
/// A SEC1-compressed secp256k1 point (33 bytes).
type EphemeralPublicKey = [u8; 33];

/// A SEC1-compressed secp256k1 point (33 bytes).
type ViewingPublicKey = [u8; 33];
/// The x-coordinate of the ECDH shared point (32 bytes).
type SharedSecretKey = [u8; 32];

struct EncryptedAccountData {
    ciphertext: Ciphertext,
    epk: EphemeralPublicKey,
    view_tag: u8,           // 1-byte view tag
}

/// BIP-340 Schnorr on secp256k1 (x-only pubkeys)
type Signature = [u8; 64];
type PublicKey = [u8; 32]; // 32-byte x-only secp256k1 public key

/// The borsh serialization of a `risc0_zkvm::InnerReceipt`.
type Proof = ByteString;

const DATA_MAX_LENGTH_IN_BYTES = 100 * 1024;
const MAX_NUMBER_CHAINED_CALLS: usize = 10;
const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];
```

> **Byte order:** LEZ uses little-endian encoding throughout for integers, with the exception of the key protocol which follows BIP-32 (big-endian).

## Accounts

All accounts (public and private) share a common schema with standard fields:

```rust
struct Account {
    program_owner: ProgramId,
    balance: NativeToken,
    data: Data,
    nonce: Nonce,
}

/// Account default value 
/// (The notation `[]` means the unique array of length zero)
impl Default for Account {
    fn default() -> Self {
        Self {
            program_owner: [0; 8],
            balance: 0,
            data: [],
            nonce: 0,
        }
    }
}
```

### Program owner field

The identification number of the program that can operate on this account's data. It's represented as a `[u32; 8]` identifier (`ProgramId`). This field ties the account to a specific program (often called the account's owner program `program_owner`) which defines the rules for how the account's data can be manipulated.

### Balance field

The number of native tokens held by the account. It's represented as a 128-bit number. That means, the total supply of the system should never exceed $2^{128} - 1$. As long as that is guaranteed, transfer operations on the balance will not overflow. This is because under normal transfer operations, no account can end up with a balance greater than the total supply of the system. NSSA prevents overflow exploits on the balance field by upcasting each term to u256 when computing the total balances before and after an execution.

### Data field

An arbitrary byte string field to be managed by the `program_owner` program. The content and interpretation of this field are defined by the program logic. The maximum size of it is defined by the constant `DATA_MAX_LENGTH_IN_BYTES`.

### Nonce field

The nonce is a 128-bit integer value. It has different uses depending on the visibility of the account:

- **Public accounts:** The nonce counts the number of transactions in which the associated public key of the account appears as a signer. This serves as a sequence number to prevent replay of transactions involving this account.
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

Private accounts use a *nullifier public key* (`Npk`) as a core identifier. The next two subsections derive `Npk` and define the account ID formats — both are prerequisites for the commitment and nullifier fields that follow.

### Nullifier public key derivation

The nullifier public key is derived from the nullifier secret key via a pure hash function:

$$\mathsf{Npk} = \mathsf{SHA256}(\text{"LEE/keys"} \;||\; \mathsf{nsk} \;||\; [7] \;||\; [0; 23])$$

The total input is 64 bytes: 8 bytes prefix + 32 bytes `nsk` + 1 byte `[7]` + 23 bytes zero padding.

```rust
impl NullifierPublicKey {
    fn from(nsk: &NullifierSecretKey) -> Self {
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[7];
        const SUFFIX_2: &[u8; 23] = &[0; 23];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(nsk);
        bytes.extend_from_slice(SUFFIX_1);
        bytes.extend_from_slice(SUFFIX_2);
        Self(sha256(bytes))
    }
}
```

### Account ID

**Public account ID:**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PUBLIC\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{public\_key})$$

```rust
/// ASCII "/LEE/v0.3/AccountId/Public/" zero-padded to 32 bytes
PUBLIC_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00"
```

**Private account ID:**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_ACCOUNT\_ID\_PREFIX} \;||\; \mathsf{Npk} \;||\; \mathsf{identifier\_le})$$

The hash input is 80 bytes: 32-byte prefix + 32-byte `Npk` + 16-byte little-endian `identifier`. Each `(Npk, identifier)` pair yields a distinct account ID, so the same set of private account keys can be reused across up to $2^{128}$ independent private accounts. One per `identifier` value.

```rust
/// ASCII "/LEE/v0.3/AccountId/Private/" zero-padded to 32 bytes
PRIVATE_ACCOUNT_ID_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00"
```

```rust
impl AccountId {
    fn from_private(npk: &NullifierPublicKey, identifier: Identifier) -> Self {
        let mut bytes = [0_u8; 80];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..80].copy_from_slice(&identifier.to_le_bytes());
        sha256(bytes)
    }
}
```

**Public program-derived account ID (public PDA):**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PUBLIC\_PDA\_PREFIX} \;||\; \mathsf{program\_id} \;||\; \mathsf{seed})$$

The hash input is 96 bytes: 32-byte prefix + 32-byte `program_id` (as 8 LE u32 words) + 32-byte `seed`.

```rust
/// ASCII "/NSSA/v0.2/AccountId/PDA/" zero-padded to 32 bytes
PUBLIC_PDA_PREFIX: [u8; 32] = b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00"
```

**Private program-derived account ID (private PDA):**

$$\mathsf{AccountId} = \mathsf{SHA256}(\mathsf{PRIVATE\_PDA\_PREFIX} \;||\; \mathsf{program\_id} \;||\; \mathsf{seed} \;||\; \mathsf{Npk} \;||\; \mathsf{identifier\_le})$$

The hash input is 144 bytes: 32 + 32 + 32 + 32 + 16. Unlike public PDAs, the private PDA derivation includes `Npk` and `identifier`. This ensures two different users at the same `(program_id, seed)` get different addresses, and a single user at `(program_id, seed, Npk)` controls a family of $2^{128}$ private PDA addresses (one per identifier value).

```rust
/// ASCII "/LEE/v0.3/AccountId/PrivatePDA/" zero-padded to 32 bytes
PRIVATE_PDA_PREFIX: [u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00"
```

```rust
impl AccountId {
    fn for_private_pda(
        program_id: &ProgramId,
        seed: &PdaSeed,
        npk: &NullifierPublicKey,
        identifier: Identifier,
    ) -> Self {
        let mut bytes = [0_u8; 144];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        let program_id_bytes: &[u8] = bytemuck::cast_slice(program_id);
        bytes[32..64].copy_from_slice(program_id_bytes);
        bytes[64..96].copy_from_slice(&seed.0);
        bytes[96..128].copy_from_slice(&npk.to_byte_array());
        bytes[128..144].copy_from_slice(&identifier.to_le_bytes());
        sha256(bytes)
    }
}
```

### Commitment

The commitment of an account is computed as:

$$\mathsf{Commitment} = \mathsf{SHA256}(\mathsf{COMMITMENT\_PREFIX} \;||\; \mathsf{account\_id} \;||\; \mathsf{ProgramOwner} \;||\; \mathsf{BalanceBytes} \;||\; \mathsf{NonceBytes} \;||\; \mathsf{DataDigest})$$

where

- `COMMITMENT_PREFIX` is the domain separator:
  ```rust
  /// ASCII "/LEE/v0.3/Commitment/" zero-padded to 32 bytes
  COMMITMENT_PREFIX: [u8; 32] = b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  ```
- `account_id` is the 32-byte account ID of the private account (which encodes both the owner's `Npk` and the `Identifier`; see the Account ID section above).
- `ProgramOwner` is the 32 bytes of the program owner field encoded as 8 little-endian `u32` words.
- `BalanceBytes` are the 16 bytes of the little-endian representation of the balance.
- `NonceBytes` are the 16 bytes of the little-endian representation of the nonce.
- `DataDigest` are the 32 bytes of the SHA256 digest of the data field.

The total preimage is 160 bytes.

```rust
impl Commitment {
    fn new(account_id: &AccountId, account: &Account) -> Self {
        const COMMITMENT_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMMITMENT_PREFIX);
        bytes.extend_from_slice(account_id.value());
        for word in &account.program_owner {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&account.balance.to_le_bytes());
        bytes.extend_from_slice(&account.nonce.to_le_bytes());
        let data_digest: [u8; 32] = sha256(&account.data);
        bytes.extend_from_slice(&data_digest);
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
    fn for_account_initialization(account_id: &AccountId) -> Self {
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
        program_id: ProgramId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}
```

The kind is serialized as a fixed 81-byte header prepended to the encrypted account data:

```
Regular(ident):                  0x00 || ident (16 bytes LE) || [0u8; 64]
Pda { program_id, seed, ident }: 0x01 || program_id (8 × u32 LE) || seed (32 bytes) || ident (16 bytes LE)
```

Both variants produce 81 header bytes, so ciphertext lengths are uniform across account types.

After decryption the receiver reconstructs the account ID from the kind:
- `Regular(ident)` → `AccountId::from_private(npk, ident)`
- `Pda { program_id, seed, ident }` → `AccountId::for_private_pda(program_id, seed, npk, ident)`

#### Key agreement and shared secret

When creating a private account output, the sender generates an ephemeral secret key `esk` and the corresponding ephemeral public key `Epk = esk * G`. The shared secret is the **x-coordinate** of the ECDH result (32 bytes, not a SEC1-compressed point):

- Sender: $\mathsf{ss} = x\text{-coordinate of } (\mathsf{esk} \cdot \mathsf{vpk\_recipient})$
- Receiver: $\mathsf{ss} = x\text{-coordinate of } (\mathsf{vsk} \cdot \mathsf{Epk\_sender})$

where `vpk` is the receiver's `ViewingPublicKey` (a 33-byte SEC1-compressed secp256k1 point) and `vsk` is the corresponding viewing secret key (a secp256k1 scalar).

#### KDF

```rust
fn kdf(
    shared_secret: &SharedSecretKey,    // 32-byte x-coordinate
    commitment: &Commitment,            // 32-byte output commitment
    output_index: u32,                  // index of this output within the tx (LE)
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NSSA/v0.2/KDF-SHA256/");
    bytes.extend_from_slice(&shared_secret.0);
    bytes.extend_from_slice(&commitment.to_byte_array());
    bytes.extend_from_slice(&output_index.to_le_bytes());
    sha256(bytes)
}
```

#### Encryption

```rust
fn encrypt(
    account: &Account,
    kind: &PrivateAccountKind,
    shared_secret: &SharedSecretKey,
    commitment: &Commitment,
    output_index: u32,
) -> Ciphertext {
    // Plaintext: 81-byte kind header || account serialization
    let mut buffer = kind.to_header_bytes().to_vec();
    buffer.extend_from_slice(&account.to_bytes());
    // Apply ChaCha20 keystream with a [0; 12] nonce
    let key = kdf(shared_secret, commitment, output_index);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);
    Ciphertext(buffer)
}
```

`account.to_bytes()` serializes the account as:
`program_owner (8 × u32 LE) || balance (16 bytes LE) || nonce (16 bytes LE) || data_len (u32 LE) || data`

#### Decryption

```rust
fn decrypt(
    ciphertext: &Ciphertext,
    shared_secret: &SharedSecretKey,
    commitment: &Commitment,
    output_index: u32,
) -> Option<(PrivateAccountKind, Account)> {
    let mut buffer = ciphertext.0.clone();
    let key = kdf(shared_secret, commitment, output_index);
    chacha20_xor(&key, &[0u8; 12], &mut buffer);

    if buffer.len() < PrivateAccountKind::HEADER_LEN {
        return None;
    }
    let header: &[u8; 81] = buffer[..81].try_into().unwrap();
    let kind = PrivateAccountKind::from_header_bytes(header)?;
    let account = Account::from_bytes(&buffer[81..]).ok()?;
    Some((kind, account))
}
```

## Programs

Programs define the logic for operating on accounts. They are stateless and can only execute instructions and modify the state of accounts passed to them. All changes to public or private accounts must be performed through program execution. There's no way to alter account state directly without invoking a program.

A program can only directly modify the state of accounts that are owned by the program. A program can queue other program executions to modify accounts owned by those programs. These queued executions are called *chained calls*.

All programs share the same function signature. They take as input:

1. The executing program's own ID.
2. The caller program's ID, or `None` if this is a top-level call.
3. A list of accounts, each annotated with metadata.
4. An instruction-specific data word list.

Programs are treated as blackboxes: given some inputs, they produce a `ProgramOutput` that represents their claimed state transition. All validation is performed on the output, never on the raw inputs. In privacy-preserving transactions the program runs inside an off-chain ZK circuit; the sequencer receives only a proof that the circuit was executed correctly, without seeing the program's inputs. In public transactions the program is executed directly, but the same output-based validation applies — this uniformity is intentional, so that the constraint rules do not differ between the two execution paths.

`ProgramOutput` is the program's complete claimed state transition and contains:

- `pre_states` — the accounts the program claims to have operated on, including their pre-execution state.
- `post_states` — the resulting account states after execution.
- `chained_calls` — queued executions of other programs.
- `self_program_id` and `caller_program_id` — used by the verifier to check that the output was produced by the expected program and invoked through the correct call chain.
- `instruction_data` — used to verify that each chained call was executed with the instruction the calling program requested.
- `block_validity_window` and `timestamp_validity_window` — range constraints on which blocks/timestamps this output is valid for.

Formally:

```rust
struct AccountWithMetadata {
    account: Account,
    is_authorized: bool,
    account_id: AccountId,
}

pub struct AccountPostState {
    account: Account,
    claim: Option<Claim>,
}

pub struct ProgramOutput {
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    instruction_data: InstructionData,
    pre_states: Vec<AccountWithMetadata>,
    post_states: Vec<AccountPostState>,
    chained_calls: Vec<ChainedCall>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
}

/// A claim request indicating the executing program intends to take ownership of an account.
pub enum Claim {
    /// Standard claim path, used for all account kinds that are not self-owned PDAs. Succeeds
    /// when the account's `is_authorized` flag is true (public accounts, public PDAs, private
    /// PDAs), or unconditionally for standalone private accounts.
    Authorized,
    /// Ownership via a PDA seed. Only valid for PDAs owned by the executing program itself:
    /// the AccountId must match the derivation from (self_program_id, seed) for public PDAs,
    /// or from (self_program_id, seed, npk, identifier) for private PDAs.
    Pda(PdaSeed),
}

pub struct ChainedCall {
    pub program_id: ProgramId,
    pub pre_states: Vec<AccountWithMetadata>,
    pub instruction_data: InstructionData,
    /// PDA seeds authorized for the callee. For each seed, the callee is authorized to
    /// mutate the AccountId derived from (caller_program_id, seed) — whether public or private.
    pub pda_seeds: Vec<PdaSeed>,
}

type Program = fn(
    ProgramId, Option<ProgramId>, List<AccountWithMetadata>, InstructionData
) -> ProgramOutput;
```

The verifier validates that a `ProgramOutput` satisfies the following constraints:

1. The output's `pre_states` contain unique account IDs. Each `AccountId` in the list is unique.
2. The output's `pre_states` and `post_states` have the same length `N`.
3. Program cannot update an account's nonce. For all `i in 0..N`, `pre_states[i].account.nonce == post_states[i].account.nonce`.
4. Program cannot change the program owner of an account. For all `i in 0..N`, `pre_states[i].account.program_owner == post_states[i].account.program_owner`.
5. Program can only decrease the native token balance for accounts that the program owns. For all `i in 0..N`, if `post_states[i].account.balance < pre_states[i].account.balance`, then `pre_states[i].account.program_owner == executing_program_id`.
6. Program can only change an account's data for accounts that the program owns (or if the account is default). For all `i in 0..N`, if `pre_states[i].account.data != post_states[i].account.data` then either `pre_states[i].account == Account::default()` or `pre_states[i].account.program_owner == executing_program_id`.
7. Any account that has default program owner after execution must have been a default account before execution. For all `i in 0..N`, if `post_states[i].account.program_owner == DEFAULT_PROGRAM_ID` then `pre_states[i].account == Account::default()`.
8. The sum of balances across all `pre_states` equals the sum across all `post_states`.

In pseudocode:

```rust
pub fn validate_execution(
    pre_states: &[AccountWithMetadata],
    post_states: &[AccountPostState],
    executing_program_id: ProgramId,
) -> Result<(), ExecutionValidationError> {
    // 1. Check account ids are all different
    if !validate_uniqueness_of_account_ids(pre_states) {
        return Err(ExecutionValidationError::PreStateAccountIdsNotUnique);
    }

    // 2. Lengths must match
    if pre_states.len() != post_states.len() {
        return Err(ExecutionValidationError::MismatchedPreStatePostStateLength { .. });
    }

    for (pre, post) in pre_states.iter().zip(post_states) {
        // 3. Nonce must remain unchanged
        if pre.account.nonce != post.account.nonce {
            return Err(ExecutionValidationError::ModifiedNonce { .. });
        }

        // 4. Program ownership changes are not allowed
        if pre.account.program_owner != post.account.program_owner {
            return Err(ExecutionValidationError::ModifiedProgramOwner { .. });
        }

        let account_program_owner = pre.account.program_owner;

        // 5. Decreasing balance only allowed if owned by executing program
        if post.account.balance < pre.account.balance
            && account_program_owner != executing_program_id
        {
            return Err(ExecutionValidationError::UnauthorizedBalanceDecrease { .. });
        }

        // 6. Data changes only allowed if owned by executing program or if account is default
        if pre.account.data != post.account.data
            && pre.account != Account::default()
            && account_program_owner != executing_program_id
        {
            return Err(ExecutionValidationError::UnauthorizedDataModification { .. });
        }

        // 7. If post state has default program owner, pre state must have been default
        if post.account.program_owner == DEFAULT_PROGRAM_ID && pre.account != Account::default() {
            return Err(ExecutionValidationError::NonDefaultAccountWithDefaultOwner { .. });
        }
    }

    // 8. Total balance is preserved
    let total_pre = WrappedBalanceSum::from_balances(pre_states.iter().map(|p| p.account.balance));
    let total_post = WrappedBalanceSum::from_balances(post_states.iter().map(|p| p.account.balance));
    if total_pre != total_post {
        return Err(ExecutionValidationError::MismatchedTotalBalance { .. });
    }

    Ok(())
}
```

The `is_authorized` flag in `AccountWithMetadata` indicates whether the account owner has provided authorization. It is the program's responsibility to check it where needed. Authorization is granted via different mechanisms depending on the account type:

- For public accounts: through digital signatures.
- For private accounts: through knowledge proofs of the corresponding nullifier secret key.
- For PDAs: through the `pda_seeds` mechanism in chained calls (and, for self-owned PDAs, via `Claim::Pda` which proves ownership by address derivation).

### Account authority vs program ownership

`is_authorized` and `program_owner` serve distinct purposes:

- `is_authorized` indicates whether the account owner has authorized the account to be used in this transaction. For public accounts this comes from a signature; for private accounts from a valid nullifier secret key proof. For PDAs it is established through the `pda_seeds` mechanism.
- `program_owner` indicates which program can mutate the account's state. It is set once via the claiming mechanism and cannot be changed by programs directly.

### Account claiming mechanism

Programs output a list of `AccountPostState`, each optionally carrying a `Claim`:

```rust
impl AccountPostState {
    /// No claim — executing program does not request ownership.
    pub fn new(account: Account) -> Self { Self { account, claim: None } }

    /// Always claims ownership with the given claim type.
    pub fn new_claimed(account: Account, claim: Claim) -> Self {
        Self { account, claim: Some(claim) }
    }

    /// Claims ownership only if account.program_owner == DEFAULT_PROGRAM_ID.
    pub fn new_claimed_if_default(account: Account, claim: Claim) -> Self {
        let is_default = account.program_owner == DEFAULT_PROGRAM_ID;
        Self { account, claim: is_default.then_some(claim) }
    }
}
```

After execution, the runtime processes each post-state's optional `claim`:

- `Claim::Authorized` — the standard claim path: sets `program_owner = executing_program_id` (when currently default) for all account kinds except self-owned PDAs. Whether `is_authorized` is required depends on the account kind:
  - **Public accounts:** `is_authorized` must be `true`, set when the transaction signer included the account in the authorized set.
  - **Public and private PDAs:** `is_authorized` must be `true`, set when the caller included the matching seed in `ChainedCall.pda_seeds`.
  - **Regular private accounts**: there's no extra enforcement for claiming. The circuit already imposes that `is_authorized` must be true for the `PrivateAuthorizedInit` and `PrivateAuthorizedUpdate` variants, and false for `PrivateUnauthorized`.
- `Claim::Pda(seed)` — sets `program_owner = executing_program_id` (when currently default) by proving the account's ID is structurally derived from the executing program's own ID and the given seed, with no user authorization required. Unlike `Claim::Authorized`, the claim is not backed by a signature or nullifier key proof; instead, the program demonstrates ownership by construction: if the address was computed from `(self_program_id, seed)`, then no other program could have produced that same address. The derivation formula depends on the account kind: for public accounts it is `AccountId::for_public_pda(executing_program_id, seed)`; for private PDAs it is `AccountId::for_private_pda(executing_program_id, seed, npk, identifier)` using the npk supplied for that pre-state, making the claim user-specific. `Claim::Pda` is not applicable to standalone private accounts.

### Program-derived account IDs (PDAs)

**Public PDA:** derived from `(program_id, seed)` — see the Account ID section above.

**Private PDA:** derived from `(program_id, seed, npk, identifier)`. Unlike public PDAs, private PDAs are per-user: two users at the same `(program_id, seed)` get different addresses. Within a single user's namespace the `identifier` diversifies further.

Authorization for private PDAs in chained calls is established by the caller including the PDA seed in `pda_seeds`. In privacy-preserving transactions, the ZK proof additionally verifies that the address matches `AccountId::for_private_pda` using the NPK supplied for that pre-state.


### Validity windows

Programs can constrain when their outputs are accepted by the sequencer:

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

An output outside its window is rejected at the sequencer level before any state transition is applied.

## NSSA v0.3 state

```rust
struct NssaState {
    public_state: Map<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
    programs: Map<ProgramId, Program>,
}
```

- `public_state`: A map from each account ID to its corresponding `Account` for all public accounts. The entire `AccountId` space is conceptually populated; account IDs not explicitly stored are treated as having default values (sparse representation).
- `private_state`: A combination of two structures tracking private account state:
  - `CommitmentSet`: An authenticated Merkle tree of all existing private account commitments.
  - `NullifierSet`: A `BTreeSet` of all revealed nullifiers.
- `programs`: A map from `ProgramId` to program bytecode for each deployed program.

The `CommitmentSet` exposes:
- `insert(element)` — add a commitment.
- `get_authentication_path_for(element)` — Merkle inclusion path.
- `compute_digest_for_path(element, proof)` — verify inclusion against a root.
- `is_current_or_previous_digest(digest)` — check against the root history.

The `NullifierSet` is a plain ordered set.


### Dummy commitment and dummy commitment hash

Two special constants are derived from the default account and the null account ID `[0; 32]`:

```rust
/// DUMMY_COMMITMENT = Commitment::new(&AccountId([0; 32]), &Account::default())
/// Concretely: SHA256(COMMITMENT_PREFIX || [0]*32 || [0]*32 || [0]*16 || [0]*16 || SHA256([]))
pub const DUMMY_COMMITMENT: Commitment = Commitment([
    55, 228, 215, 207, 112, 221, 239, 49, 238, 79, 71, 135, 155, 15, 184, 45, 104, 74, 51, 211,
    238, 42, 160, 243, 15, 124, 253, 62, 3, 229, 90, 27,
]);

pub const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    250, 237, 192, 113, 155, 101, 119, 30, 235, 183, 20, 84, 26, 32, 196, 229, 154, 74, 254, 249,
    129, 241, 118, 39, 41, 253, 141, 171, 184, 71, 8, 41,
];
```

`DUMMY_COMMITMENT` is the commitment of the default account (`Account::default()`) under the null account ID (`[0; 32]`). It is not a real user account: no keys exist that could spend it, so it can never be nullified.

At genesis, the `CommitmentSet` is initialized by inserting `DUMMY_COMMITMENT` as its first entry. This bootstraps the Merkle tree before any real private accounts exist and gives the set a well-defined root from the very first state. Because the Merkle tree hashes each leaf as `SHA256(value)`, the root of a tree containing only `DUMMY_COMMITMENT` is `SHA256(DUMMY_COMMITMENT)` — which is exactly `DUMMY_COMMITMENT_HASH`. As a result, `DUMMY_COMMITMENT_HASH` is permanently present in the `CommitmentSet`'s `root_history` from genesis onward.

**Role in initialization nullifiers.** Every nullifier submitted in a `PrivacyPreservingTransaction` must be paired with a `CommitmentSetDigest`. For update nullifiers this is the Merkle root that was current when the sender computed their membership proof. For **init nullifiers** — emitted when a private account is created for the first time (`PrivateAuthorizedInit`, `PrivateUnauthorized`, `PrivatePdaInit`) — no prior commitment exists to be spent, so there is no natural Merkle root to cite. Rather than special-casing this in the sequencer's acceptance logic, init nullifiers uniformly use `DUMMY_COMMITMENT_HASH` as their digest. Since `DUMMY_COMMITMENT_HASH` is always in `root_history`, the standard `root_history.contains(digest)` check accepts them without any extra branching — the same validation path covers both init and update nullifiers.


## Built-in programs

See [docs/builtin_programs.md](builtin_programs.md). Additional user-defined programs may also be deployed via `ProgramDeploymentTransaction` (see "State transition from program deployment transactions").

## Protected system accounts

Certain accounts are reserved and cannot be modified by user-submitted transactions. The sequencer enforces this to every user transaction before any state mutation. Only sequencer-originated transactions bypass this check.

The three clock accounts and the system faucet account are protected by a post-execution diff check. After a transaction's state diff is produced for all transaction types (public, privacy-preserving, or program deployment). The sequencer inspects whether any of the protected accounts appear with a changed value. If so, the transaction is rejected:

This check fires after execution, so it catches indirect modifications (e.g. a program that receives a clock account as a pre-state and attempts to alter it).
The only transactions that may update the protected accounts are:
- the sequencer's own clock invocations, which are inserted at the end of the block after user transactions.
- The genesis execution of the faucet program used for initial supply distribution.

## Structure of a public transaction

```rust
struct Message {
    program_id: ProgramId,
    account_ids: List<AccountId>,
    nonces: List<Nonce>,
    instruction_data: InstructionData,
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

- `program_id`: The `ProgramId` of the program to invoke.
- `account_ids`: The list of relevant account IDs that the program will operate on.
- `nonces`: One nonce per signer (public account). Each must match the current nonce of the corresponding account in state.
- `instruction_data`: Parameters encoded as a list of `u32` words.

### Witness set

A list of `(signature, public_key)` pairs. Each pair must produce a valid BIP-340 Schnorr signature over the message hash. The accounts derived from each `public_key` (via `AccountId::from(&public_key)`) form the *authorized signer set*. The program receives `is_authorized = true` for any pre-state account in this set (programs use the flag to decide whether to permit user-driven actions like transfers). Programs may also gain authorization for additional accounts via the PDA mechanism in chained calls. Authorization propagates down the call chain monotonically: the authorized set passed to each child call is the union of the parent's own authorized set and the parent's verified authorized pre-states, so an account authorized at any hop remains authorized for all subsequent calls even if an intermediate hop does not include it in its pre-states. Upon acceptance, each signing account's nonce is incremented by 1.

## Structure of a privacy-preserving transaction

```rust
struct Message {
    public_account_ids: List<AccountId>,
    nonces: List<Nonce>,
    public_post_states: List<Account>,
    encrypted_private_post_states: List<EncryptedAccountData>,
    new_commitments: List<Commitment>,
    new_nullifiers: List<(Nullifier, CommitmentSetDigest)>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
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

1. `public_account_ids`: Account IDs of all public accounts involved.
2. `nonces`: One nonce per signing public account.
3. `public_post_states`: New states of any public accounts modified by this transaction.
4. `encrypted_private_post_states`: Encrypted details of each new private account output, decryptable by the respective recipient.
5. `new_commitments`: New commitment values added to the `CommitmentSet`.
6. `new_nullifiers`: Nullifiers revealed by this transaction, each paired with the `CommitmentSetDigest` of the commitment being spent.
7. `block_validity_window` / `timestamp_validity_window`: Time-bound constraints propagated from the `ProgramOutput`. Outputs outside their window are rejected.

### Witness set

- `signatures_and_public_keys`: BIP-340 Schnorr signature pairs for any public accounts requiring authorization.
- `proof`: A borsh-serialized `risc0_zkvm::InnerReceipt` proving correct execution of the privacy-preserving circuit.

## The privacy-preserving execution circuit

The circuit is a RISC-V program proven with the risc0 zkVM. It is executed entirely off-chain by the transaction sender; the sequencer only verifies the proof. It is not a built-in program in the NSSA sense — it wraps the execution of built-in programs inside a ZK proof.

**Workflow:**
The circuit takes as private inputs a `PrivacyPreservingCircuitInput`: the sequence of `ProgramOutput`s for each call in the execution chain, one `InputAccountIdentity` per pre-state (carrying nullifier secret keys, shared secret keys, membership proofs, and identifiers as required by each account variant), and the top-level program ID.

1. Verify that each `ProgramOutput` in the chain has a valid proof of execution for the corresponding program.
2. Verify that `validate_execution` passes for each program call.
3. Check that chained-call instruction data, accounts, and `is_authorized` flags are consistent across caller/callee boundaries, using the same `CallerData`-based authorization propagation as the public execution path: the initial `authorized_accounts` is the set of public accounts whose `is_authorized` flag is `true` in the top-level `public_pre_states` (i.e. the signers), and each hop propagates its authorized pre-states to child calls. The total number of calls must not exceed `MAX_NUMBER_CHAINED_CALLS + 1` (same bound enforced in the public acceptance criteria).
4. For each account:
   - Public: collect pre/post state; increment nonce if authorized.
   - Private init: verify pre-state is default; derive account_id; compute init nullifier; set nonce via `nonce_init`; encrypt post-state.
   - Private update: verify membership proof; compute update nullifier; increment nonce via `nonce_increment`; encrypt post-state.
5. Emit `PrivacyPreservingCircuitOutput`.

**Transaction-wide private PDA family binding.** The same `(program_id, seed)` pair can produce different program-derived account IDs for different `npk` and `identifier`. This creates a subtle authorization hazard: a caller that places seed `S` in `pda_seeds` intends to authorize exactly one account to the callee. Without an additional constraint, however, a callee could present two private PDA pre-states that both derive from `(caller_program_id, S)` and the single seed entry would authorize both.

To close this, the circuit enforces the following rule across an entire transaction:

> Each `(program_id, seed)` pair may resolve to **at most one** account ID for the duration of the transaction.

The rule applies to both the `Claim::Pda(seed)` path and the `pda_seeds` authorization path. Every time either path resolves an account under a given `(program_id, seed)`, the resolved account ID is recorded. A later resolution of the same pair must agree with the recorded account ID, or the transaction is rejected.

In pseudocode:

```rust
// Checked at every Claim::Pda(seed) and at every pda_seeds match, for both public and private PDAs.
fn record_or_assert_pda_binding(
    bindings: &mut Map<(ProgramId, Seed), AccountId>,
    program_id: ProgramId,
    seed: Seed,
    resolved_account_id: AccountId,
) {
    match bindings.get((program_id, seed)) {
        None => bindings.insert((program_id, seed), resolved_account_id),
        Some(existing) => assert_eq!(
            existing, resolved_account_id,
            "two different accounts resolved under (program_id, seed) in one transaction",
        ),
    }
}
```

### Circuit input

```rust
pub struct PrivacyPreservingCircuitInput {
    /// Outputs of the program execution chain.
    pub program_outputs: Vec<ProgramOutput>,
    /// One entry per pre-state, in the same order as they appear across program_outputs.
    pub account_identities: Vec<InputAccountIdentity>,
    /// Top-level program ID.
    pub program_id: ProgramId,
}

pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from program_outputs and emits no
    /// commitment, ciphertext, or nullifier.
    Public,

    /// Initialization of a standalone private account the caller owns.
    /// Pre-state must be Account::default().
    /// AccountId = AccountId::from_private(npk(nsk), identifier).
    PrivateAuthorizedInit {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
        identifier: Identifier,
    },

    /// Update of an existing standalone private account the caller owns.
    /// Membership proof for the current on-chain commitment is required.
    PrivateAuthorizedUpdate {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
    },

    /// Initialization of a standalone private account the caller does not own
    /// (e.g. a recipient who does not yet exist on chain). No nsk, no membership proof.
    PrivateUnauthorized {
        npk: NullifierPublicKey,
        ssk: SharedSecretKey,
        identifier: Identifier,
    },

    /// Initialization of a private PDA.
    /// Authorization comes via Claim::Pda(seed) or the caller's pda_seeds.
    /// The identifier diversifies the PDA within the (program_id, seed, npk) family.
    PrivatePdaInit {
        npk: NullifierPublicKey,
        ssk: SharedSecretKey,
        identifier: Identifier,
    },

    /// Update of an existing private PDA. npk is derived from nsk.
    /// Membership proof is required.
    PrivatePdaUpdate {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
    },
}
```

The `ssk` field carries the **shared secret key** — the 32-byte x-coordinate of the ECDH shared point used to encrypt the post-state. Note that the key protocol uses `ssk` for "spending secret key" (the master key that derives `nsk` and `vsk`); here `ssk` means the per-output ECDH shared secret. It is computed in two equivalent ways:

- Sender: `ssk = x-coordinate of (esk · vpk_recipient)`
- Receiver: `ssk = x-coordinate of (vsk · Epk_sender)`

where `esk`/`Epk` are the ephemeral key pair, `vpk` is the recipient's viewing public key, and `vsk` is the corresponding viewing secret key.

### Circuit output

```rust
pub struct PrivacyPreservingCircuitOutput {
    pub public_pre_states: Vec<AccountWithMetadata>,
    pub public_post_states: Vec<Account>,
    pub ciphertexts: Vec<Ciphertext>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
}
```

### Circuit logic summary

For each `InputAccountIdentity` the circuit performs the following:

| Variant | AccountId derivation | Nonce init | Nullifier emitted | Auth required | `Claim::Authorized` precondition |
|---------|---------------------|------------|-------------------|---------------|-----------------------------------|
| `Public` | from pre-state | +1 if authorized | none | signature | `is_authorized` must be `true` |
| `PrivateAuthorizedInit` | `from_private(npk(nsk), ident)` | `nonce_init(account_id)` | init nullifier | nsk | `is_authorized` must be `true` |
| `PrivateAuthorizedUpdate` | `from_private(npk(nsk), ident)` | `nonce_increment(nsk)` | update nullifier | nsk + membership proof | **not enforced** (skipped) |
| `PrivateUnauthorized` | `from_private(npk, ident)` | `nonce_init(account_id)` | init nullifier | none | **not enforced** (skipped) |
| `PrivatePdaInit` | `for_private_pda(prog, seed, npk, ident)` | `nonce_init(account_id)` | init nullifier | pda_seeds/Claim::Pda, or CallerData propagation | `is_authorized` must be `true` |
| `PrivatePdaUpdate` | `for_private_pda(prog, seed, npk(nsk), ident)` | `nonce_increment(nsk)` | update nullifier | (pda_seeds or CallerData) + nsk + membership proof | `is_authorized` must be `true` |

For each private account the post-state commitment is `Commitment::new(account_id, post_account)` (with the new nonce applied). The ciphertext is `EncryptionScheme::encrypt(post_account, kind, ssk, commitment, output_index)`.

The chain-of-calls logic and `validate_execution` rules are identical to the public execution path. The claiming rules diverge for **standalone private accounts only**: `Claim::Authorized` on a `Regular` private kind is allowed unconditionally (no `is_authorized` check). For public accounts and private PDAs, `Claim::Authorized` enforcement matches the public path.


## Encrypted private account discovery and tagging

### Ephemeral view tags

Each private account output includes a 1-byte view tag to allow wallets to quickly filter outputs before attempting decryption:

$$\mathsf{ViewTag} = \mathsf{SHA256}(\text{"/LEE/v0.3/ViewTag/"} \;||\; \mathsf{Npk} \;||\; \mathsf{vpk})[0]$$

where `Npk` is the 32-byte nullifier public key and `vpk` is the 33-byte SEC1-compressed `ViewingPublicKey` of the recipient. On average only 1 in 256 outputs will pass this filter for a given account, avoiding expensive ECDH on irrelevant outputs.

### Private account discovery with viewing keys

1. For each encrypted output, compute the expected view tag from `(Npk, vpk)`. Skip if it does not match.
2. Perform ECDH: `ss = x-coordinate of (vsk * Epk)`.
3. Run `kdf(ss, commitment, output_index)` to derive the symmetric key.
4. Decrypt the ciphertext with ChaCha20.
5. Parse the 81-byte header to recover `PrivateAccountKind`.
6. Parse the remaining bytes to recover the `Account`.
7. Recompute the account ID from the kind and verify that `Commitment::new(account_id, account)` equals the on-chain commitment. Discard on mismatch (false positive).

```rust
fn private_account_discovery(
    tx: &PrivacyPreservingTransaction,
    vsk: &ViewingSecretKey,
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
) -> Vec<(PrivateAccountKind, Account)> {
    let expected_tag = EncryptedAccountData::compute_view_tag(npk, vpk);
    let mut discovered = Vec::new();

    for (output_index, (encrypted_account, commitment)) in tx.message.encrypted_private_post_states
        .iter()
        .zip(&tx.message.new_commitments)
        .enumerate()
    {
        if encrypted_account.view_tag != expected_tag {
            continue;
        }
        let ss = SharedSecretKey::new(vsk, &encrypted_account.epk);
        if let Some((kind, account)) = EncryptionScheme::decrypt(
            &encrypted_account.ciphertext, &ss, commitment, output_index as u32
        ) {
            let account_id = AccountId::for_private_account(npk, &kind);
            if Commitment::new(&account_id, &account) == *commitment {
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
| Nullifier — initialization | `b"/LEE/v0.3/Nullifier/Initialize/\x00"` |
| Nullifier — update | `b"/LEE/v0.3/Nullifier/Update/\x00\x00\x00\x00\x00"` |
| Account ID — public | `b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00"` |
| Account ID — private | `b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00"` |
| Account ID — public PDA | `b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00"` |
| Account ID — private PDA | `b"/LEE/v0.3/AccountId/PrivatePDA/\x00"` |
| Nullifier public key (from NSK) | `b"LEE/keys"` + nsk + `[7]` + `[0; 23]` |
| KDF | `b"NSSA/v0.2/KDF-SHA256/"` |
| View tag | `b"/LEE/v0.3/ViewTag/"` |
| Public transaction message hash | `b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00"` |
| Privacy transaction message hash | `b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00"` |

## Public transaction acceptance criteria

For a public transaction to be accepted and applied to the state:

- **No duplicate account IDs:** The `account_ids` list must not contain repeated entries.
- **Signature/nonce count match:** The number of nonces in the message must equal the number of `(signature, public_key)` pairs in the witness set.
- **Valid signatures:** All BIP-340 Schnorr signatures must verify against the message hash.
- **Nonce checks:** For each signing account, the nonce in the transaction must match the account's current nonce in state.
- **Program existence:** The `program_id` must correspond to a deployed program.
- **Valid execution:** The program is invoked with the provided accounts and instruction data. `validate_execution` must pass. At each call in the chain, an account in `pre_states` receives `is_authorized = true` if it is either a top-level signer (derived from a public key in the witness set), a PDA explicitly seeded by the immediate caller via `pda_seeds`, or an account that was `is_authorized` in the parent program's verified pre-states (authorization propagates down the call chain).
- **Pre-state consistency:** Each `program_output.pre_states[i]` must equal the current state of `pre_states[i].account_id` (or the diffed value from earlier chained calls). The `is_authorized` flag in each pre-state must match the actual authorization status.
- **Program identity consistency:** Each program output's `self_program_id` must equal the program ID it was invoked under, and its `caller_program_id` must equal the caller (or `None` for the top-level call).
- **Validity window enforcement:** For *each* `ProgramOutput` in the chain (top-level and chained calls), the current `block_id` must fall within `program_output.block_validity_window` and the current `timestamp` must fall within `program_output.timestamp_validity_window`. Out-of-window outputs are rejected.
- **Maximum chained-call depth:** The total number of chained call executions (not including the top-level call) must not exceed `MAX_NUMBER_CHAINED_CALLS`.
- **Claiming:** Any `AccountPostState` with a `Claim` causes the runtime to set `program_owner = executing_program_id` for that account, but only if the account's current `program_owner == DEFAULT_PROGRAM_ID`. In the public path all accounts are public, so `Claim::Authorized` always requires `is_authorized == true` (signature, or PDA via caller's `pda_seeds`), and `Claim::Pda(seed)` requires the account ID to match `AccountId::for_public_pda(executing_program_id, seed)`. (The privacy path relaxes the `Claim::Authorized` precondition for standalone private accounts — see the Programs section.)
- **No silent default-account modifications:** Any account whose pre-state has `program_owner == DEFAULT_PROGRAM_ID` and whose post-state differs from the pre-state must have been claimed (i.e. its post-state `program_owner` is no longer the default).

In pseudocode:

```rust
fn validate_and_produce_public_state_diff(
    tx: PublicTransaction,
    nssa_state: NssaState,
    block_id: BlockId,
    timestamp: Timestamp,
) -> Map<AccountId, Account> {
    let message = tx.message;
    let witness_set = tx.witness_set;

    // No duplicate account ids
    assert_no_duplicates(message.account_ids);

    // One nonce per signature
    assert_eq!(message.nonces.len(), witness_set.signatures_and_public_keys.len());

    // Verify signatures and nonces
    let mut signer_account_ids = [];
    for ((signature, public_key), nonce) in witness_set.signatures_and_public_keys.zip(message.nonces) {
        assert!(signature.is_valid_for(message.hash(), public_key));
        let account_id = AccountId::from(public_key);
        assert_eq!(nssa_state.public_state.get(account_id).nonce, nonce);
        signer_account_ids.push(account_id);
    }

    let input_pre_states = message.account_ids.map(|id| AccountWithMetadata {
        account: nssa_state.public_state.get(id),
        is_authorized: signer_account_ids.contains(id),
        account_id: id,
    });

    let mut state_diff = {};

    // The chained-call queue. Each entry carries the call to execute and the program ID
    // of its caller (None for the top-level call).
    let initial_call = ChainedCall {
        program_id: message.program_id,
        instruction_data: message.instruction_data,
        pre_states: input_pre_states,
        pda_seeds: [],
    };

    struct CallerData {
        program_id: Option<ProgramId>,
        /// Accounts that were `is_authorized` in the parent program's verified pre-states.
        /// For the top-level call this is the signer set; for chained calls it propagates
        /// from the parent's authorized pre-states, enabling multi-hop authorization.
        authorized_accounts: Set<AccountId>,
    }

    let initial_caller_data = CallerData {
        program_id: None,
        authorized_accounts: signer_account_ids,
    };

    let mut queue = [(initial_call, initial_caller_data)];
    let mut counter = 0;

    while let Some((call, caller_data)) = queue.pop_front() {
        assert!(counter <= MAX_NUMBER_CHAINED_CALLS);

        let program = nssa_state.programs.get(call.program_id);
        let program_output = program.execute(
            call.program_id,
            caller_data.program_id,
            call.pre_states,
            call.instruction_data,
        );

        // Compute the set of public PDAs the callee is authorized to mutate via the
        // caller's pda_seeds. For the top-level call (caller_data.program_id == None) this is
        // always the empty set.
        let authorized_pdas = compute_public_authorized_pdas(caller_data.program_id, call.pda_seeds);
        // An account is authorized if it was in the parent's authorized set (propagated from
        // its verified pre-states) or if it is a PDA the caller explicitly seeded.
        let is_authorized = |account_id| {
            caller_data.authorized_accounts.contains(account_id)
                || authorized_pdas.contains(account_id)
        };

        // Verify pre-state and authorization consistency: programs cannot fabricate inputs.
        for pre in program_output.pre_states {
            let expected_pre = state_diff.get(pre.account_id)
                .unwrap_or(nssa_state.public_state.get(pre.account_id));
            assert_eq!(pre.account, expected_pre);
            // The is_authorized flag must exactly match the actual authorization status:
            // programs cannot forge it (flag true on an unauthorized account) nor
            // under-report it (flag false on a truly-authorized account).
            assert_eq!(pre.is_authorized, is_authorized(pre.account_id));
        }

        // Verify the output identifies its own program ID and caller correctly.
        assert_eq!(program_output.self_program_id, call.program_id);
        assert_eq!(program_output.caller_program_id, caller_data.program_id);

        validate_execution(
            program_output.pre_states,
            program_output.post_states,
            call.program_id,
        );

        // Validity window: this output is valid only within its declared block / timestamp range.
        assert!(program_output.block_validity_window.is_valid_for(block_id));
        assert!(program_output.timestamp_validity_window.is_valid_for(timestamp));

        // Apply claims and update the state diff.
        for (pre, post) in program_output.pre_states.zip(program_output.post_states) {
            if let Some(claim) = post.claim {
                // Claims only fire when the account currently has the default program owner.
                assert_eq!(post.account.program_owner, DEFAULT_PROGRAM_ID);
                match claim {
                    Claim::Authorized => assert!(pre.is_authorized),
                    Claim::Pda(seed) => {
                        assert_eq!(pre.account_id, AccountId::for_public_pda(call.program_id, seed));
                    }
                }
                post.account.program_owner = call.program_id;
            }
            state_diff.insert(pre.account_id, post.account);
        }

        // Build the authorized set for child calls: the union of the caller's authorized set
        // and the verified authorized pre-states of this call. Using program_output.pre_states
        // (not call.pre_states) ensures the new entries are derived from already-validated data
        // and cannot be forged by a caller-supplied input. Authorization is monotonically
        // growing — once an account is authorized at any point in the chain it remains
        // authorized for all subsequent calls, even if an intermediate hop does not include
        // it in its own pre-states.
        let authorized_accounts = caller_data.authorized_accounts
            .union(
                program_output.pre_states
                    .filter(|pre| pre.is_authorized)
                    .map(|pre| pre.account_id)
            );

        // Push chained calls (in declared order). Pushing them to the front of the queue
        // produces a depth-first traversal.
        for new_call in program_output.chained_calls.reversed() {
            queue.push_front((new_call, CallerData {
                program_id: Some(call.program_id),
                authorized_accounts: authorized_accounts,
            }));
        }

        counter += 1;
    }

    // Default-owner accounts that were modified must have been claimed.
    for (account_id, post) in state_diff {
        let pre = nssa_state.public_state.get(account_id);
        if pre.program_owner == DEFAULT_PROGRAM_ID && pre != post {
            assert_ne!(post.program_owner, DEFAULT_PROGRAM_ID);
        }
    }

    state_diff
}
```

### Note on replay attacks

The nonce mechanism ensures authorized public transactions cannot be replayed. Once accepted, nonces for all signing accounts are incremented — the same transaction can never be valid again. Purely unauthorized transactions (no signatures required) could theoretically be replayed.

## Privacy-preserving transaction acceptance criteria

For a privacy transaction to be accepted:

- **Non-empty commitments or nullifiers:** At least one new commitment or nullifier must be present.
- **No duplicate public account IDs:** The `public_account_ids` list must not contain repeated entries.
- **Commitment uniqueness:** No two entries within the transaction's `new_commitments` list may be equal.
- **Commitment freshness:** No new commitment may already exist in the `CommitmentSet`.
- **Nullifier uniqueness:** No new nullifier may already exist in the `NullifierSet`. No duplicates within the transaction's `new_nullifiers` list either.
- **Valid commitment set digests:** Each nullifier's associated `CommitmentSetDigest` must match a current or previous digest of the `CommitmentSet`.
- **Signature/nonce count match:** The number of nonces in the message must equal the number of `(signature, public_key)` pairs in the witness set.
- **Nonce checks and valid signatures:** Same rules as for public transactions, applied to any public accounts present.
- **Validity window enforcement:** The current `block_id` must fall within `message.block_validity_window` and the current `timestamp` must fall within `message.timestamp_validity_window`. These windows are the intersection of all per-`ProgramOutput` windows in the chain, computed and committed by the circuit.
- **Proof verification:** The ZK proof must verify against the circuit output values in the message and the current public pre-states. Public accounts in `public_pre_states` receive `is_authorized = true` if they are top-level signers; the circuit then applies the same `CallerData`-based authorization propagation as the public execution path, so authorized accounts (including PDAs) flow through chained calls as described there.

In pseudocode:

```rust
fn verify_privacy_preserving_transaction(
    tx: PrivacyPreservingTransaction,
    nssa_state: NssaState,
    block_id: BlockId,
    timestamp: Timestamp,
) {
    let message = tx.message;
    let witness_set = tx.witness_set;

    // 1. Non-empty
    assert!(!message.new_commitments.is_empty() || !message.new_nullifiers.is_empty());

    // 2. No duplicate public account ids
    assert_no_duplicates(message.public_account_ids);

    // 3. Commitment uniqueness within the transaction
    assert_no_duplicates(message.new_commitments);

    // 4. Nullifier uniqueness within the transaction
    assert_no_duplicates(message.new_nullifiers.map(|(n, _)| n));

    // 5. Nonce checks and valid signatures
    assert_eq!(witness_set.signatures_and_public_keys.len(), message.nonces.len());
    let mut authorized_ids = [];
    for ((sig, pk), nonce) in witness_set.signatures_and_public_keys.zip(message.nonces) {
        assert!(sig.is_valid_for(message.hash(), pk));
        let account_id = AccountId::from(pk);
        assert_eq!(nssa_state.public_state.get(account_id).nonce, nonce);
        authorized_ids.push(account_id);
    }

    // 6. Validity window enforcement
    assert!(message.block_validity_window.is_valid_for(block_id));
    assert!(message.timestamp_validity_window.is_valid_for(timestamp));

    // 7. Build public pre-states for proof verification
    let public_pre_states = message.public_account_ids.map(|id| AccountWithMetadata {
        account: nssa_state.public_state.get(id),
        is_authorized: authorized_ids.contains(id),
        account_id: id,
    });

    // 8. Proof verification
    assert_privacy_circuit_proof_is_valid(
        witness_set.proof,
        public_pre_states,
        message.public_post_states,
        message.encrypted_private_post_states.map(|e| e.ciphertext),
        message.new_commitments,
        message.new_nullifiers,
        message.block_validity_window,
        message.timestamp_validity_window,
    );

    // 9. Commitment freshness and valid digests are checked against the current CommitmentSet
    //    and NullifierSet.
    for commitment in message.new_commitments {
        assert!(!nssa_state.private_state.0.contains(commitment));
    }
    for (nullifier, digest) in message.new_nullifiers {
        assert!(!nssa_state.private_state.1.contains(nullifier));
        assert!(nssa_state.private_state.0.is_current_or_previous_digest(digest));
    }
}
```

### Note on replay attacks

Replay attacks are not possible for privacy transactions. Any accepted transaction either adds commitments or nullifiers to the state. A replay attempt is rejected by commitment freshness or nullifier uniqueness checks.

## State transitions

### State transition from public transactions

1. Verify acceptance criteria — including the per-`ProgramOutput` validity windows — and produce a state diff.
2. Apply the state diff: update (or insert) each account in `public_state`.
3. Increment nonces for all signing accounts.

```rust
fn transition_from_public_transaction(
    tx: PublicTransaction,
    nssa_state: NssaState,
    block_id: BlockId,
    timestamp: Timestamp,
) {
    let state_diff = validate_and_produce_public_state_diff(tx, nssa_state, block_id, timestamp);

    for (account_id, post) in state_diff {
        nssa_state.public_state[account_id] = post;
    }

    for account_id in tx.signer_account_ids() {
        nssa_state.public_state[account_id].nonce += 1;
    }
}
```

### State transition from privacy-preserving transactions

1. Verify acceptance criteria — including the message's validity windows.
2. Add new commitments to the `CommitmentSet`.
3. Add new nullifiers to the `NullifierSet`.
4. Apply public account changes from `public_post_states`.
5. Increment nonces for all signing public accounts.

```rust
fn transition_from_privacy_preserving_transaction(
    tx: PrivacyPreservingTransaction,
    nssa_state: NssaState,
    block_id: BlockId,
    timestamp: Timestamp,
) {
    verify_privacy_preserving_transaction(tx, nssa_state, block_id, timestamp);

    for commitment in tx.message.new_commitments {
        nssa_state.private_state.0.insert(commitment);
    }

    for (nullifier, _) in tx.message.new_nullifiers {
        nssa_state.private_state.1.insert(nullifier);
    }

    for (account_id, post) in tx.message.public_account_ids.zip(tx.message.public_post_states) {
        nssa_state.public_state[account_id] = post;
    }

    for account_id in tx.signer_account_ids() {
        nssa_state.public_state[account_id].nonce += 1;
    }
}
```

For both transaction types, the validity-window check is part of the acceptance criteria — outputs outside their declared windows are rejected before any state mutation occurs.

### State transition from program deployment transactions

A program deployment transaction contains only the program bytecode. The program ID is derived from the bytecode image.

```rust
struct ProgramDeploymentMessage {
    bytecode: ByteString,
}

struct ProgramDeploymentTransaction {
    message: ProgramDeploymentMessage,
}
```

1. Verify the derived `ProgramId` does not already exist in `programs`.
2. Insert the new program.

```rust
fn transition_from_program_deployment_transaction(
    tx: &ProgramDeploymentTransaction,
    nssa_state: &mut NssaState,
) {
    let program = Program::new(tx.message.bytecode.clone()).expect("Valid program bytecode");
    assert!(!nssa_state.programs.contains_key(&program.id()), "Program already deployed");
    nssa_state.programs.insert(program.id(), program);
}
```
