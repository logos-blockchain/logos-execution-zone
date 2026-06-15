# LEE Key Protocol

## LEE Key Protocol basic types and constants

```rust
/// Public account keys
struct PrivateKey([u8; 32]);
struct PublicKey([u8; 32]);

/// Private account keys
struct SecretSpendingKey([u8; 32]);
type NullifierSecretKey = [u8; 32];
struct NullifierPublicKey([u8; 32]);
struct ViewingSecretKey { d: [u8; 32], z: [u8; 32] }
type ViewingPublicKey = MlKem768EncapsulationKey; // 1184 bytes — ML-KEM 768 encapsulation key

/// Signing related keys
```

## HD wallet

LEE’s HD wallet derives all account keys from a single mnemonic phrase ([BIP-039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)). The mnemonic generates a `seed` that roots two independent key subtrees: one for public state accounts (based on [BIP-032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) and one for private state accounts (based on [ZIP-032](https://zips.z.cash/zip-0032)).

Each parent-to-child edge is parametrized by an index. A key is uniquely addressed by its path from the root. E.g. `m_pub/0/4/12` is the 12th child of the 4th child of the 0th child of the public master key; `m_priv/0/4/12` is the analogous path for private accounts.

During key discovery, LEE stops searching a node’s children after 20 consecutive unused indices (following Bitcoin’s gap-limit convention).

## Seed

The seed is the single secret from which all wallet keys are derived. It is 64 bytes, generated from a BIP-039 mnemonic phrase via PBKDF2-HMAC-SHA512:

```rust
// SeedHolder::new_mnemonic / new_os_random
let mnemonic = Mnemonic::from_entropy(&entropy_bytes); // 24-word phrase from 32 random bytes
let seed: [u8; 64] = mnemonic.to_seed(passphrase);    // PBKDF2, 2048 iterations
```

The seed is the only value derived directly from the mnemonic. Both key subtrees are rooted from it, distinguished by their HMAC key string:

```rust
// Public root
let hash_value = hmac_sha512::HMAC::mac(seed, b"LEE_master_pub");

// Private root
let hash_value = hmac_sha512::HMAC::mac(seed, b"LEE_master_priv");
```

In both cases the 64-byte HMAC output is split the same way: the first 32 bytes become the subtree's root secret key and the last 32 bytes become its root chain code.

The seed is never stored on-chain.

## Public account keys

Public accounts consist of three keys (secret key `sk`, Schnorr secret key `ssk` and public key `pk`). Additionally, auxiliary values chain index `ci` and chain code `cc`. Public account keys are generated using their chain index and their parent's chain code.

```rust
pub struct ChildKeysPublic {
    pub sk: PrivateKey,
    pub ssk: PrivateKey,
    pub pk: PublicKey,
    pub cc: [u8; 32],
    /// Can be [`None`] if root.
    pub cci: Option<u32>
}
```

### Secret key

The secret key (`sk`) is used for generating the Schnorr secret key. Currently, the secret key is not directly used in LEE. Rather, the Schnorr secret key (`ssk`) is used for managing the public account. At some point in the future, Schnorr signatures (and `ssk`) will be phased out. At that point, `sk` will be used for authorization in a PQ signature scheme.

The secret key `sk` is computed using one of two different methods. The method used depends on whether the account key is the root key or a child key.

#### Secret key for root public account
```rust
let sk = nssa::PrivateKey::try_new(
    *hash_value
        .first_chunk::<32>()
        .expect("hash_value is 64 bytes, must be safe to get first 32"),
    )
```

#### Secret key for child public account
```rust
let hash_value = self.compute_hash_value(cci);

let lhs = k256::Scalar::from_repr(
    (*hash_value
        .first_chunk::<32>()
        .expect("hash_value is 64 bytes, must be safe to get first 32"))
    .into(),
)
.expect("Expect a valid k256 scalar");

let rhs = k256::Scalar::from_repr((*self.sk.value()).into())
    .expect("Expect a valid k256 scalar");

let sk = nssa::PrivateKey::try_new(lhs.add(&rhs).to_bytes().into())
    .expect("Expect a valid private key");
```

In both cases, the chain code `cc` is the last 32 bytes of `hash_value`.

### Schnorr secret key

The Schnorr secret key (`ssk`) is used for managing public ownership and authorization Authorization for spending funds and, in some cases, modifying account data is handled by signing the transaction with the account’s Schnorr secret key. The Schnorr secret key serves as protective layer between the account's secret key and quantum attackers.

The Schnorr secret key (`ssk`) is computed from the secret key (`sk`) as follows:
1. `private_key` is the scalar associated in the basefield for `secp256k1` generated from `sk`.
2. `public_key` is the corresponding (compressed) public key in `secp256k1`.
3. `ssk = private_key + Sha256(public_key)` where the hash of `public_key` is parsed as a scalar.

```rust
    pub fn tweak(value: &[u8; 32]) -> Result<Self, NssaError> {
        if !Self::is_valid_key(*value) {
            return Err(NssaError::InvalidPrivateKey);
        }
 
        let sk = k256::SecretKey::from_slice(value).map_err(|_e| NssaError::InvalidPrivateKey)?;

        let hashed: [u8; 32] = Impl::hash_bytes(sk.public_key().to_encoded_point(true).as_bytes()) 
            .as_bytes()
            .try_into()
            .expect("Sha256 outputs a 32-byte array");

        let sk = sk.to_nonzero_scalar();

        let scalar = k256::Scalar::from_repr(hashed.into())
            .into_option()
            .ok_or(NssaError::InvalidPrivateKey)?;

        Self::try_new(sk.add(&scalar).to_bytes().into())
    }
```

```rust
let ssk = nssa::PrivateKey::tweak(sk.value()).expect("Invalid private key produced from `tweak`");
```

### Public key

A public account’s public key (`pk`) is used to verify account ownership. Specifically, the public key is used to validate (Schnorr) signatures purporting to authorizing an account’s usage. The public key is the x-only Schnorr public key (32 bytes, BIP-340).

## Private account keys

Private accounts consist of three types of keys: secret spending key `ssk`, nullifier keys (`nsk`, `npk`), and viewing keys (`vsk`, `vpk`). Additionally, auxiliary values chain index `ci` and chain code `cc`. Private account keys are generated using their chain index and their parent's chain code.

Each private account's key data are stored in `ChildKeysPrivate`.
```rust
pub struct ChildKeysPrivate {
    pub value: (KeyChain, BTreeMap<PrivateAccountKind, nssa::Account>),
    pub ccc: [u8; 32],
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}
```

Unlike public account keys, private account keys can be used for multiple accounts. A list (`BTreeMap`) is used to store all private accounts that use the same set of private account keys. `KeyChain` bundle all of the secret keys.

```rust
pub struct KeyChain {
    pub secret_spending_key: SecretSpendingKey,
    pub private_key_holder: PrivateKeyHolder,  // holds nsk and vsk
    pub nullifier_public_key: NullifierPublicKey,
    pub viewing_public_key: ViewingPublicKey,
}

pub struct PrivateKeyHolder {
    pub nullifier_secret_key: NullifierSecretKey,
    pub viewing_secret_key: ViewingSecretKey,
}
```

### Secret key

The `SecretSpendingKey` (`ssk`) is the root secret for a private account node. It is never transmitted or stored on-chain; all other keys are derived from it.

For both the root and each child, the `ssk` is a 32-byte value taken from the first half of an HMAC-SHA512 output.

#### Secret key generation for root

Root private keys are derived from the BIP-039 seed via HMAC-SHA512 keyed with `"LEE_master_priv"`. The 64-byte output is split: the first 32 bytes become the `SecretSpendingKey` (`ssk`) and the last 32 bytes become the child chain code (`ccc`).

```rust
let hash_value = hmac_sha512::HMAC::mac(seed, b"LEE_master_priv");

let ssk = SecretSpendingKey(
    *hash_value.first_chunk::<32>().expect("64-byte output"),
);
let ccc = *hash_value.last_chunk::<32>().expect("64-byte output");
```

#### Secret key generation for child keys

Child keys are derived from the parent's `PrivateKeyHolder` (via a SHA-256 "parent point" commitment) and the parent's `ccc`, mixed with the child index `cci`. The scheme follows ZIP-032 in spirit.

```rust
// 1. Commit to the parent's secret material
let mut parent_hash = sha2::Sha256::new();
parent_hash.update(b"LEE/keys");
parent_hash.update(parent.private_key_holder.nullifier_secret_key);
parent_hash.update(parent.private_key_holder.viewing_secret_key.d);
parent_hash.update(parent.private_key_holder.viewing_secret_key.z);
let parent_pt = parent_hash.finalize(); // 32 bytes

// 2. Derive child ssk and ccc
let mut input = vec![];
input.extend_from_slice(b"LEE_seed_priv");
input.extend_from_slice(&parent_pt);
input.extend_from_slice(&cci.to_be_bytes()); // big-endian per BIP-032

let hash_value = hmac_sha512::HMAC::mac(input, parent.ccc);

let ssk = SecretSpendingKey(*hash_value.first_chunk::<32>().expect("64-byte output"));
let ccc = *hash_value.last_chunk::<32>().expect("64-byte output");
```

### Nullifier keys

The nullifier secret key (`nsk`) and nullifier public key (`npk`) are derived from the `ssk` and child index. The `npk` is used to compute the `AccountId` for a private account and to generate nullifiers when an account is spent.

**`nsk` derivation** — SHA-256 keyed with domain-separation bytes and the child index:

```rust
// SecretSpendingKey::generate_nullifier_secret_key
let mut hasher = sha2::Sha256::new();
hasher.update(b"LEE/keys");  // 8 bytes
hasher.update(self.0);       // 32 bytes ssk
hasher.update([1_u8]);       // 1 byte type tag for nsk
hasher.update(index.to_be_bytes()); // 4 bytes
hasher.update([0_u8; 19]);   // 19 bytes padding

let nsk: NullifierSecretKey = hasher.finalize_fixed().into();
```
The `root` private account does not have an `index` (`None`). The `index` is treated as `0_u32` in this case.


**`npk` derivation** — SHA-256 (risc0 implementation) of domain-prefixed `nsk`:

```rust
// NullifierPublicKey::from(&nsk)
let mut bytes = Vec::new();
bytes.extend_from_slice(b"LEE/keys"); // 8 bytes
bytes.extend_from_slice(&nsk);        // 32 bytes
bytes.extend_from_slice(&[7_u8]);     // 1 byte type tag for npk
bytes.extend_from_slice(&[0_u8; 23]);  // 23 bytes padding

let npk = NullifierPublicKey(risc0_sha256(&bytes));
```

The nullifier secret key and nullifier public key include constants (`1_u8` and `7_u8`). These constants are used to avoid collision of inputs between nullifier secret keys and nullifier public keys.

### Viewing keys

The viewing secret key (`vsk`) is a 64-byte ML-KEM 768 seed split into two 32-byte halves `d` and `z`. The viewing public key (`vpk`) is the corresponding ML-KEM 768 encapsulation key (1184 bytes). The `vsk` allows the holder to decrypt ciphertexts sent to the account; the `vpk` is the address component senders use to encrypt.

**`vsk` derivation** — HMAC-SHA512 over a 64-byte domain-tagged input:

```rust
// SecretSpendingKey::generate_viewing_secret_seed_key
let mut bytes: [u8; 64] = [0; 64];
// b"LEE/keys" (8) || ssk (32) || [2] (1) || index.to_be_bytes() (4) || [0; 19] (19) = 64
bytes[0..8].copy_from_slice(b"LEE/keys");
bytes[8..40].copy_from_slice(&self.0);
bytes[40] = 2; // type tag for vsk
bytes[41..45].copy_from_slice(&index.to_be_bytes());
// bytes[45..64] remain 0

let full_seed = hmac_sha512::HMAC::mac(bytes, b"LEE_viewing_seed");

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

**Shared secret (receiver side)** — ML-KEM 768 decapsulation using `vsk.d` and `vsk.z`:

```rust
// KeyChain::calculate_shared_secret_receiver
let shared_secret = SharedSecretKey::decapsulate(&ephemeral_public_key, &vsk.d, &vsk.z);
```
