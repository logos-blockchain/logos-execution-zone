# LEZ v0.3 specifications for Key Agreement

## LEZ v0.3 basic types and constants

```rust
/// The ML-KEM-768 KEM ciphertext produced during encapsulation (1088 bytes) of a message.
/// `EphemeralPublicKey` is used to not confuse the ciphertext of an encrypted private account.
type EphemeralPublicKey = [u8; 1088];

/// Private account Viewing Public Key is a ML-KEM-768 encapsulation key (1184 bytes).
type ViewingPublicKey = [u8; 1184];
/// The ML-KEM-768 shared secret (32 bytes).
type SharedSecretKey = [u8; 32];

struct EncryptedAccountData {
    ciphertext: Ciphertext,
    epk: EphemeralPublicKey,
    view_tag: u8,           // 1-byte view tag
}
```

#### Key agreement and shared secret

When creating a private account output, the sender uses the recipient's viewing public key to encapsulate a random message that is used to establish a shared secret between the sender and recipient:

- Sender: $(\mathsf{ss},\, \mathsf{epk}) = \mathsf{encapsulate}(\mathsf{vpk\_recipient})$. The 1088-byte ciphertext `epk` is included in the transaction as the `EphemeralPublicKey` field.
- Receiver: $\mathsf{ss} = \mathsf{decapsulate}(\mathsf{epk},\, vsk.d,\, vks.r)$

where `vpk` is the receiver's `ViewingPublicKey` and `(vsk.d, vsk.r)` are the two 32-byte halves of the receiver's `ViewingSecretKey`.

#### KDF

```rust
fn kdf(
    shared_secret: &SharedSecretKey,    // 32-byte output of the KEM
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

### Circuit input

```rust
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

The `ssk` field carries the **shared secret key** — the 32-byte shared secret used to encrypt the post-state. Note that the key protocol uses `ssk` for "spending secret key" (the master key that derives `nsk` and `vsk`); here `ssk` means the per-output KEM shared secret. It is established via ML-KEM-768:

- Sender: `(ssk, epk) = encapsulate(vpk)`
- Receiver: `ssk = decapsulate(epk, vsk.d, vsk.r)`

where `epk` is the ML-KEM-768 ciphertext (1088 bytes) stored as the `EphemeralPublicKey`, `vpk` is the recipient's `ViewingPublicKey` (1184 bytes), and `(vsk.d, vsk.r)` are the 32-byte seed halves of the recipient's `ViewingSecretKey`.

## Encrypted private account discovery and tagging

### Ephemeral view tags

Each private account output includes a 1-byte view tag to allow wallets to quickly filter outputs before attempting decryption:

$$\mathsf{ViewTag} = \mathsf{SHA256}(\text{"/LEE/v0.3/ViewTag/"} \;||\; \mathsf{Npk} \;||\; \mathsf{Vpk})[0]$$

where `Npk` is the 32-byte nullifier public key and `Vpk` is the 1184 byte `ViewingPublicKey` of the recipient. On average only 1 in 256 outputs will pass this filter for a given account, avoiding expensive ECDH on irrelevant outputs.

### Private account discovery with viewing keys

1. For each encrypted output, compute the expected view tag from `(Npk, Vpk)`. Skip if it does not match.
2. Decapsulate using ML-KEM-768: `ss = decapsulate(epk, vsk.d, vsk.r)`.
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
        let ss = SharedSecretKey::decapsulate(&encrypted_account.epk, &vsk.d, &vsk.r);
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
