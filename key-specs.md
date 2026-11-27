# LEE Key Protocol (v0.4)

## LEE Key Protocol basic types and constants

```rust
/// Public account keys
struct PublicAccountSecret([u8; 32]);
enum KeyType { Schnorr = 0 }            // a signing key's signature scheme; may be extended (e.g. hash-based)
type KeyCommitment = [u8; 32];

/// Signing key types
// Schnorr (BIP-340)
struct PrivateKey([u8; 32]);
struct PublicKey([u8; 32]);             // x-only
type SchnorrAuthData = [u8; 96];        // signature (64 bytes) || public key (32 bytes)

/// Private account keys
struct SecretSpendingKey([u8; 32]);
struct AuthorizationSecretKey([u8; 32]);
type NullifierSecretKey = [u8; 32];
struct NullifierPublicKey([u8; 32]);
struct ViewingSecretKey { d: [u8; 32], z: [u8; 32] }
type ViewingPublicKey = MlKem768EncapsulationKey; // 1184 bytes — ML-KEM 768 encapsulation key

/// Ephemeral encryption keys — per-output, not part of the HD key tree
struct EphemeralSecretKey([u8; 32]);  // `esk`: ML-KEM encapsulation randomness
struct EphemeralPublicKey(Vec<u8>);   // `epk`: ML-KEM ciphertext, on-wire, 1088 bytes
struct SharedSecretKey([u8; 32]);     // KDF input shared by sender and receiver

/// Group keys — shared secret across multiple controllers of a private PDA/account
struct GroupKeyHolder { gms: [u8; 32] } // `gms`: Group Master Secret
struct SealingPublicKey(Vec<u8>);       // ML-KEM 768 encapsulation key, used to seal a `GroupKeyHolder` for a recipient
type SealingSecretKey = ViewingSecretKey;
```

## HD wallet

LEE’s HD wallet derives all account keys from a single mnemonic phrase ([BIP-039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)). The mnemonic generates a `seed` that roots two independent key subtrees: one for public state accounts (inspired by [BIP-032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) and one for private state accounts (inspired by [ZIP-032](https://zips.z.cash/zip-0032)).

Each parent-to-child edge is parametrized by an index. A key is uniquely addressed by its path from the root. E.g. `m_pub/0/4/12` is the 12th child of the 4th child of the 0th child of the public master key; `m_priv/0/4/12` is the analogous path for private accounts.

When restoring from a mnemonic, the wallet regenerates every node whose path weight (the sum of each index plus one, e.g. `m_pub/0/4/12` weighs 1 + 5 + 13 = 19) is below a chosen depth. It then removes uninitialized nodes from the deepest layer upward, stopping at the first node in use; a private node is also kept while a pending message awaits it. New accounts take the first free slot of the lowest weight.

## Seed

The seed is the single secret from which all wallet keys are derived. It is 64 bytes, generated from a BIP-039 mnemonic phrase via PBKDF2-HMAC-SHA512:

```rust
// SeedHolder::new_mnemonic / from_mnemonic
let mnemonic = Mnemonic::from_entropy(&entropy_bytes); // 24-word phrase from 32 random bytes
let seed: [u8; 64] = mnemonic.to_seed(passphrase);    // PBKDF2, 2048 iterations
```

The protocol supports any BIP-039 passphrase. The LEE wallet currently hardcodes the empty passphrase (`""`); other wallets may use a non-empty one.

The seed is the only value derived directly from the mnemonic. Both key subtrees are rooted from it, distinguished by their HMAC key string:

```rust
// Public root
let hash_value = hmac_sha512::HMAC::mac(seed, b"/LEE-Keys/v1/Master/Public");

// Private root
let hash_value = hmac_sha512::HMAC::mac(seed, b"/LEE-Keys/v1/Master/Private");
```

The first 32 bytes of each 64-byte output become the subtree's root secret: the root `PublicAccountSecret` and the root `SecretSpendingKey`. The private root also takes the last 32 bytes as its root chain code; the public subtree has no chain codes.

The seed is never stored on-chain.

## Public account keys

Public accounts consist of a single secret, the public account secret (`secret`), and an auxiliary value (the chain index `cci`). Each public account secret is generated using the account's chain index and the parent's secret.

```rust
pub struct ChildKeysPublic {
    pub secret: PublicAccountSecret,
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}
```

The public account secret is never used to sign. Instead, it generates the account's current authorization key. The authorization key is stateful: it depends on the account's `nonce` and the selected signing key type, so it changes with every authorized transaction (see [Authorization and key rotation](#authorization-and-key-rotation)).

### Public account secret

The public account secret is computed using one of two different methods. The method used depends on whether the account is the root or a child.

#### Public account secret for root public account

```rust
let hash_value = hmac_sha512::HMAC::mac(seed, b"/LEE-Keys/v1/Master/Public");

let secret = PublicAccountSecret::new(
    *hash_value.first_chunk::<32>().expect("64-byte output"),
);
```

#### Public account secret for child public account

```rust
// ChildKeysPublic::nth_child
let mut input = vec![];
input.extend_from_slice(b"/LEE-Keys/v1/Child/Public");
input.extend_from_slice(&cci.to_be_bytes()); // big-endian per BIP-032

let hash_value = hmac_sha512::HMAC::mac(input, parent.secret.value());

let secret = PublicAccountSecret::new(
    *hash_value.first_chunk::<32>().expect("64-byte output"),
);
```

In both cases, the last 32 bytes of `hash_value` are discarded: public accounts have no chain code.

### Authorization key

At each nonce, a public account has one authorization key, of the signing key type chosen for that nonce. The key is derived from the public account secret in two steps: a per-nonce key seed, then the key type's key generation.

```rust
// signing_keys::key_seed
const DS_KEY_SEED: &[u8; 32] =
    b"/LEE/v0.3/KeySeed/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

let mut hasher = sha2::Sha256::new();
hasher.update(DS_KEY_SEED);
hasher.update(secret.value());          // 32 bytes
hasher.update([key_type as u8]);        // 1 byte
hasher.update(nonce.0.to_le_bytes());   // 16 bytes
let key_seed: [u8; 32] = hasher.finalize().into();

let (sk, pk) = K::keygen(&key_seed);    // K: the signing key type
```

Authorization keys are not stored; they are re-derived from the public account secret when needed. Each signing key type commits its public key to a 32-byte `KeyCommitment`, which is what the account stores (see [Authorization and key rotation](#authorization-and-key-rotation)).

### Signing key types

Each signing key type defines how an authorization key pair is generated from the key seed. The list of key types may be extended (e.g. hash-based).

#### Schnorr (`KeyType::Schnorr = 0`)

BIP-340 Schnorr signatures over `secp256k1`. The secret key is the first of 256 candidates that is a valid `secp256k1` scalar; the public key is its x-only public key (32 bytes).

```rust
// Schnorr::keygen
const DS_KEYGEN: &[u8; 32] = b"/LEE/v0.3/KeyGen/Schnorr/\x00\x00\x00\x00\x00\x00\x00";

let sk = (0..=u8::MAX)
    .find_map(|ctr| {
        let mut hasher = sha2::Sha256::new();
        hasher.update(DS_KEYGEN);
        hasher.update(key_seed);
        hasher.update([ctr]);
        PrivateKey::try_new(hasher.finalize().into()).ok()
    })
    .expect("one of 256 candidates is a valid scalar");

let pk = PublicKey::new_from_private_key(&sk);
```

### Account ID

A public account's `AccountId` is derived from the commitment to its nonce-0 authorization key. The derivation is the same for every signing key type, except for a 32-byte prefix specific to the key type. The account ID is fixed at creation and does not change when the authorization key rotates.

```rust
// AccountId::for_initial_key
const PUBLIC_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

// Key-type prefix
const PREFIX_SCHNORR: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/Schn/";

let key_hash = risc0_sha256(key_type_prefix || key_commitment);
let account_id = AccountId(risc0_sha256(PUBLIC_ACCOUNT_ID_PREFIX || key_hash));
```

Currently, the nonce-0 authorization key is always of type Schnorr.

## Authorization and key rotation

A public account is authorized by signing with its current authorization key. Each authorized transaction also carries the commitment to the account's next authorization key (its signing key state); once the transaction settles, this replaces the account's stored signing key state. Only commitments are stored on chain, never the keys themselves.

### Signing key state

An account's current authorization key is stored on chain as its `SigningKeyState`: the key's signing key type (1 byte) and its commitment (32 bytes).

```rust
pub struct SigningKeyState {
    pub key_type: KeyType,
    pub key_commitment: KeyCommitment,
}
```

The signing key state is stored in the account as the actor state of the signature program (`signature_program_id()`), borsh-encoded as 33 bytes (`key_type || key_commitment`). Only settlement writes it; no program can. An account with no stored signing key state can be authorized only at nonce 0, against its initial key (see [Account ID](#account-id)).

### Key commitment

Each signing key type defines how its public key is committed to a `KeyCommitment`.

#### Schnorr

The commitment is a hash of the public key, so the public key is not published until the account signs with it.

```rust
// Schnorr::commit
const DS_KEY: &[u8; 32] = b"/LEE/v0.3/KeyCommitment/Schnorr/";

let mut hasher = sha2::Sha256::new();
hasher.update(DS_KEY);
hasher.update(pk.value());     // 32 bytes, x-only
let key_commitment: KeyCommitment = hasher.finalize().into();
```

### Authentication data and signature verification

To authorize a transaction, each signer provides authentication data for its current key, together with the signing key state it rotates to (`next`).

Authentication data is not only a signature. The account stores only a commitment to its current key, so the authentication data must also carry what is needed to check the signature against that commitment. Its format depends on the current key's signing key type.

#### Schnorr

`SchnorrAuthData` (96 bytes): the BIP-340 signature (64 bytes) followed by the public key (32 bytes).

The authentication data is checked in two steps:

1. Key check: the provided public key must commit to the account's current `key_commitment` (see [Key commitment](#key-commitment)). This shows the public key is the account's current authorization key.
2. Signature check: the provided signature must be a valid BIP-340 signature of `message_with_keys` (see [Signed message](#signed-message)) under that public key.

Both checks are needed: a valid signature under any other public key fails the key check, and the current public key without a valid signature fails the signature check.

#### Initial key

At nonce 0, when the account has no stored signing key state, the authentication data is prefixed with the 33-byte borsh encoding of the initial key, which must give the signer's account ID. The rest of the authentication data is checked against the initial key as above.

### Signed message

Every signer signs the same 32-byte value, `message_with_keys`: a hash of the transaction message together with every signer's next signing key state (its next key's type and commitment). Each signature therefore also covers the commitment each signer rotates to.

```rust
// hash_with_keys
const KEYED_PREFIX: &[u8; 32] = b"/LEE/v0.3/KeyedMessage/Public/\x00\x00";   // public transactions
// const KEYED_PREFIX: &[u8; 32] = b"/LEE/v0.3/KeyedMessage/Privacy/\x00"; // privacy-preserving transactions

let mut hasher = sha2::Sha256::new();
hasher.update(KEYED_PREFIX);
hasher.update(message_hash);
for next in next_keys {        // the signers' next keys, ordered by account ID
    hasher.update(borsh::to_vec(next).expect("33 bytes"));
}
let message_with_keys: [u8; 32] = hasher.finalize().into();
```

`message_hash` is `Sha256(PREFIX || borsh(message))`, under `b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00"` for public transactions and `b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00"` for privacy-preserving transactions.

### Authentication and rotation

Each signer is authenticated as follows:

1. The signer's nonce in the message must equal its account's nonce.
2. The current key is the account's stored signing key state or, at nonce 0 with none stored, the initial key prefixing the authentication data.
3. The authentication data is checked against the current key, according to its signing key type (see [Authentication data and signature verification](#authentication-data-and-signature-verification)).

When the transaction settles, each signer's nonce is incremented and its stored signing key state becomes its `next`. This also holds when the transaction is reverted and charged.

The protocol does not check how `next` was derived. The LEE wallet sets `next` to the account's authorization key at the next nonce (see [Authorization key](#authorization-key)); its signing key type may differ from the current key's.

## Private account keys

Private accounts consist of four types of keys: secret spending key `ssk`, authorization key `ask`, nullifier keys (`nsk`, `npk`), and viewing keys (`vsk`, `vpk`). Additionally, auxiliary values chain index `cci` and child chain code `ccc`. Private account keys are generated using their chain index, their parent's keys and their parent's child chain code.

Each private account's key data are stored in `ChildKeysPrivate`.

```rust
pub struct ChildKeysPrivate {
    pub value: (KeyChain, BTreeMap<PrivateAccountKind, lee::Account>),
    pub ccc: [u8; 32],
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}
```

Unlike public account keys, private account keys can be used for multiple accounts. A list (`BTreeMap`) is used to store all private accounts that use the same set of private account keys. `KeyChain` bundle all of the secret keys.

```rust
pub struct KeyChain {
    pub secret_spending_key: SecretSpendingKey,
    pub private_key_holder: PrivateKeyHolder,  // holds ask and vsk
    pub nullifier_public_key: NullifierPublicKey,
    pub viewing_public_key: ViewingPublicKey,
}

pub struct PrivateKeyHolder {
    pub authorization_secret_key: AuthorizationSecretKey,
    pub viewing_secret_key: ViewingSecretKey,
}
```

### Secret key

The `SecretSpendingKey` (`ssk`) is the root secret for a private account node. It is never transmitted or stored on-chain; all other keys are derived from it.

For both the root and each child, the `ssk` is a 32-byte value taken from the first half of an HMAC-SHA512 output.

#### Secret key generation for root

Root private keys are derived from the BIP-039 seed via HMAC-SHA512 keyed with `"/LEE-Keys/v1/Master/Private"`. The 64-byte output is split: the first 32 bytes become the `SecretSpendingKey` (`ssk`) and the last 32 bytes become the child chain code (`ccc`).

```rust
let hash_value = hmac_sha512::HMAC::mac(seed, b"/LEE-Keys/v1/Master/Private");

let ssk = SecretSpendingKey(
    *hash_value.first_chunk::<32>().expect("64-byte output"),
);
let ccc = *hash_value.last_chunk::<32>().expect("64-byte output");
```

#### Secret key generation for child keys

Child keys are derived from the parent's `PrivateKeyHolder` (via a SHA-256 "parent point" commitment) and the parent's `ccc`, mixed with the child index `cci`. The scheme is inspired by ZIP-032.

```rust
// 1. Commit to the parent's secret material
let mut parent_hash = sha2::Sha256::new();
parent_hash.update(b"/LEE-Keys/v1/Parent/Private");
parent_hash.update(parent.private_key_holder.nullifier_secret_key());
parent_hash.update(parent.private_key_holder.viewing_secret_key.d);
parent_hash.update(parent.private_key_holder.viewing_secret_key.z);
let parent_pt = parent_hash.finalize(); // 32 bytes

// 2. Derive child ssk and ccc
let mut input = vec![];
input.extend_from_slice(b"/LEE-Keys/v1/Seed/Private");
input.extend_from_slice(&parent_pt);
input.extend_from_slice(&cci.to_be_bytes()); // big-endian per BIP-032

let hash_value = hmac_sha512::HMAC::mac(input, parent.ccc);

let ssk = SecretSpendingKey(*hash_value.first_chunk::<32>().expect("64-byte output"));
let ccc = *hash_value.last_chunk::<32>().expect("64-byte output");
```

### Authorization key

The authorization secret key (`ask`) sits between the `ssk` and the nullifier keys: it is derived from `ssk` and the child index, and the nullifier secret key (`nsk`, see Nullifier keys below) is derived from `ask` rather than from `ssk` directly.

**`ask` derivation** — SHA-256 of domain-prefixed `ssk` and the child index:

```rust
// SecretSpendingKey::generate_authorization_secret_key
const DOMAIN: &[u8; 33] = b"/LEE-Keys/v1/Authorization/Secret";

let mut hasher = sha2::Sha256::new();
hasher.update(DOMAIN);
hasher.update(self.0);       // 32 bytes ssk
hasher.update(index.to_be_bytes()); // 4 bytes

let ask = AuthorizationSecretKey(hasher.finalize_fixed().into());
```

The `root` private account does not have an `index` (`None`). The `index` is treated as `0_u32` in this case.

### Nullifier keys

The nullifier secret key (`nsk`) is derived from the authorization secret key (`ask`); the nullifier public key (`npk`) is derived from `nsk`. The `npk` is used to compute the `AccountId` for a private account and to generate nullifiers when an account is spent.

**`nsk` derivation** — SHA-256 (risc0 implementation) of domain-prefixed `ask`:

```rust
// NullifierSecretKey::from(&AuthorizationSecretKey)
const DOMAIN: &[u8; 29] = b"/LEE-Keys/v1/Nullifier/Secret";

let mut bytes = [0_u8; 29 + 32];
bytes[..29].copy_from_slice(DOMAIN);
bytes[29..].copy_from_slice(&ask.0);

let nsk: NullifierSecretKey = risc0_sha256(&bytes);
```

**`npk` derivation** — SHA-256 (risc0 implementation) of domain-prefixed `nsk`:

```rust
// NullifierPublicKey::from(&nsk)
let mut bytes = Vec::new();
bytes.extend_from_slice(b"/LEE-Keys/v1/Nullifier/Public"); // 29 bytes
bytes.extend_from_slice(&nsk);        // 32 bytes

let npk = NullifierPublicKey(risc0_sha256(&bytes));
```

The nullifier secret key and nullifier public key each use a distinct domain-separation string (`/LEE-Keys/v1/Nullifier/Secret` and `/LEE-Keys/v1/Nullifier/Public`). These strings are used to avoid collision of inputs between nullifier secret keys and nullifier public keys.

### Viewing keys

The viewing secret key (`vsk`) is a 64-byte ML-KEM 768 seed split into two 32-byte halves `d` and `z`. The viewing public key (`vpk`) is the corresponding ML-KEM 768 encapsulation key (1184 bytes). The `vsk` allows the holder to decrypt ciphertexts sent to the account; the `vpk` is the address component senders use to encrypt.

**`vsk` derivation** — HMAC-SHA512 over a 63-byte domain-tagged input:

```rust
// SecretSpendingKey::generate_viewing_secret_seed_key
let mut bytes: [u8; 63] = [0; 63];
// b"/LEE-Keys/v1/Viewing/Secret" (27) || ssk (32) || index.to_be_bytes() (4) = 63
bytes[0..27].copy_from_slice(b"/LEE-Keys/v1/Viewing/Secret");
bytes[27..59].copy_from_slice(&self.0);
bytes[59..63].copy_from_slice(&index.to_be_bytes());

let full_seed = hmac_sha512::HMAC::mac(bytes, b"/LEE-Keys/v1/Viewing/Seed");

let vsk = ViewingSecretKey {
    d: *full_seed.first_chunk::<32>().expect("64-byte output"),
    z: *full_seed.last_chunk::<32>().expect("64-byte output"),
};
```

**`vpk` derivation** — ML-KEM 768 encapsulation key from seed:

```rust
// ViewingPublicKey::from(&vsk)
let vpk = MlKem768EncapsulationKey::from_seed(&vsk.d, &vsk.z); // 1184 bytes
```

## Private account encryption

### Ephemeral secret key

Every private account output (init or update) is encrypted using ML-KEM 768 encapsulation with the account owner's `vpk`. Normally, encapsulation relies on randomness but the encapsulation is performed in a deterministic environment (privacy preserving circuit in Risc0). To facilitate this design, encapsulation uses an `EphemeralSecretKey` (`esk`) that is generated using the account's `AccountId`, the account's new `Nonce` state and a random seed (32 bytes). The random seed is fed into the privacy preserving circuit from the wallet.

```rust
// EphemeralSecretKey::new
const PREFIX: &[u8; 14] = b"/LEE/v0.3/esk/";
let mut input = [0_u8; 14 + 32 + 32 + 16];
input[0..14].copy_from_slice(PREFIX);
input[14..46].copy_from_slice(account_id.value());
input[46..78].copy_from_slice(random_seed);
input[78..94].copy_from_slice(&nonce.0.to_le_bytes());
let esk = EphemeralSecretKey(Impl::hash_bytes(&input).as_bytes().try_into().unwrap());
```

- `account_id` guarantees that private accounts with the same private keys (but different identifiers) are not encrypted using the same shared secret.
- `nonce` guarantees that the same private account is never encrypted using the same shared secret key.
- A private account's `nonce` is derived from its nullifier secret key (`nsk`) at every transition, initialization included, so `esk` carries `nsk`-derived entropy and stays strong even if `random_seed` comes from a compromised RNG.

### Ephemeral public key and shared secret

The Ephemeral public key and shared secret are generated by the sender with ML-KEM encapsulation. On the recipient's side the shared secret key is recovered with decapsulation using the ephemeral public key and their viewing secret key (`vsk.d`, `vsk.z`).

**Sender side**

```rust
// SharedSecretKey::encapsulate_deterministic (circuit + wallet path)
let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &esk);

// SharedSecretKey::encapsulate — #[cfg(feature = "host")], e.g. tests
let (shared_secret, epk) = SharedSecretKey::encapsulate(&vpk);
```

**Receiver side** — ML-KEM 768 decapsulation using `vsk.d` and `vsk.z`:

```rust
// KeyChain::calculate_shared_secret_receiver
let shared_secret = SharedSecretKey::decapsulate(&ephemeral_public_key, &vsk.d, &vsk.z);
```

### Deriving the encryption key

The account state is encrypted using a symmetric key derived from the shared secret key described above. `SharedSecretKey` is passed through a SHA256 KDF, together with the note's `Nullifier`, to produce the ChaCha20 key that encrypts the note:

```rust
// EncryptionScheme::kdf
const PREFIX: &[u8; 20] = b"LEE/v0.3/KDF-SHA256/";
let mut bytes = [0_u8; 20 + 32 + 32];
bytes[0..20].copy_from_slice(PREFIX);
bytes[20..52].copy_from_slice(&shared_secret.0);
bytes[52..84].copy_from_slice(&nullifier.to_byte_array());

let key: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
let mut cipher = ChaCha20::new(&key.into(), &[0; 12].into());
```

Binding `nullifier` into the KDF means the same `shared_secret` yields a different ChaCha20 key per note, even in the (disallowed but theoretically possible) case that an `esk`/`epk` pair were ever reused. The nonce passed to `ChaCha20::new` is fixed at all zeros — freshness comes entirely from the KDF, not from the cipher nonce.

## Group keys for private account

A group of controllers can jointly own private PDAs or shared regular accounts by deriving keys from a common Group Master Secret (GMS) instead of an individual `ssk`. Any controller holding the GMS can independently derive the same `PrivateKeyHolder`.

```rust
pub struct GroupKeyHolder {
    gms: [u8; 32],
}
```

The GMS is a 32-byte random value shared among the group's controllers. It is a long-term secret and must never cross a trust boundary in raw form.

### Deriving keys for a private PDA

**Per-PDA `ssk`** — SHA-256 of domain-prefixed GMS, program id, and PDA seed:

```rust
// GroupKeyHolder::secret_spending_key_for_pda
const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeyDerivation/SSK";

let mut hasher = sha2::Sha256::new();
hasher.update(PREFIX);
hasher.update(self.gms);
for word in program_id {
    hasher.update(word.to_le_bytes());
}
hasher.update(pda_seed.as_ref());

let ssk = SecretSpendingKey(hasher.finalize_fixed().into());
```

The resulting `ssk` is then fed through the same `produce_private_key_holder` path used for a personal account (deriving `ask`, `nsk`, `npk`, `vsk`, `vpk` — see Authorization key, Nullifier keys, and Viewing keys, above), with `index = None`:

```rust
// GroupKeyHolder::derive_keys_for_pda
let private_key_holder = Self::secret_spending_key_for_pda(program_id, pda_seed)
    .produce_private_key_holder(None);
```

### Deriving keys for a shared (non-PDA) account

Uses a distinct domain separator from the PDA path above, so the same `derivation_seed` bytes can never collide across the two paths:

```rust
// GroupKeyHolder::derive_keys_for_shared_account
const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeyDerivation/SHA";

let mut hasher = sha2::Sha256::new();
hasher.update(PREFIX);
hasher.update(self.gms);
hasher.update(derivation_seed); // 32 bytes, stable and unique per shared account

let ssk = SecretSpendingKey(hasher.finalize_fixed().into());
let private_key_holder = ssk.produce_private_key_holder(None);
```

For a shared *regular* account, `derivation_seed` is computed from a wallet-local 32-byte `derivation_id` via its own domain separator before delegating to the derivation above:

```rust
// GroupKeyHolder::derive_regular_shared_account_keys
const PREFIX: &[u8; 32] = b"/LEE/v0.3/SharedAccountTag/\x00\x00\x00\x00\x00";

let mut hasher = sha2::Sha256::new();
hasher.update(PREFIX);
hasher.update(derivation_id); // 32 bytes

let derivation_seed: [u8; 32] = hasher.finalize().into();
```

### Sealing and distribution

Controllers distribute the GMS off-chain by sealing it under each recipient's `SealingPublicKey` — a recipient's `vpk`, reused in this role to keep a group's sealing keys tied to the same viewing-key material senders already use to address that recipient. Sealing uses ML-KEM-768 encapsulation to derive a shared secret, then AES-256-GCM to encrypt the GMS under a key derived from that shared secret via its own domain-separated SHA-256 KDF:

```rust
// GroupKeyHolder::seal_kdf
const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeySeal/AES\x00\x00\x00\x00\x00\x00";

let mut hasher = sha2::Sha256::new();
hasher.update(PREFIX);
hasher.update(shared.0);

let aes_key: [u8; 32] = hasher.finalize_fixed().into();
```

The sealed payload is `kem_ciphertext (1088 bytes) || nonce (12 bytes) || AES-GCM(gms) with tag (48 bytes)`. Each seal generates a fresh KEM encapsulation, so two seals of the same GMS produce different ciphertexts.

Recovery reverses the process: ML-KEM-768 decapsulation with the recipient's `SealingSecretKey` (`d`/`z` — literally a `ViewingSecretKey`, reused in this role) recovers the shared secret, which re-derives the AES key and decrypts the GMS.