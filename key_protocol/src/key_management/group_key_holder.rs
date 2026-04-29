use aes_gcm::{Aes256Gcm, KeyInit as _, aead::Aead as _};
use nssa_core::{
    SharedSecretKey,
    encryption::{Scalar, ViewingPublicKey, shared_key_derivation::Secp256k1Point},
    program::PdaSeed,
};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, digest::FixedOutput as _};

use super::secret_holders::{PrivateKeyHolder, SecretSpendingKey, ViewingSecretKey};

/// Manages shared viewing keys for a group of controllers owning private PDAs.
///
/// The Group Master Secret (GMS) is a 32-byte random value shared among controllers.
/// Each private PDA owned by the group gets a unique [`SecretSpendingKey`] derived from
/// the GMS by mixing the PDA seed into the SHA-256 input (see `secret_spending_key_for_pda`).
///
/// # Distribution
///
/// The GMS is a long-term secret and must never cross a trust boundary in raw form.
/// Controllers share it off-chain by sealing it under each recipient's [`ViewingPublicKey`]
/// (see `seal_for` / `unseal`). Wallets persisting a `GroupKeyHolder` must encrypt it at
/// rest; the raw bytes are exposed only via [`GroupKeyHolder::dangerous_raw_gms`], which
/// is intended for the sealing path exclusively.
///
/// # Logging safety
///
/// `Debug` is implemented manually to redact the GMS; formatting this value with `{:?}`
/// will not leak the secret. Code that formats through `{:#?}` on containing types is
/// safe for the same reason.
#[derive(Serialize, Deserialize, Clone)]
pub struct GroupKeyHolder {
    gms: [u8; 32],
    epoch: u32,
}

impl std::fmt::Debug for GroupKeyHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKeyHolder")
            .field("gms", &"<redacted>")
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl Default for GroupKeyHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupKeyHolder {
    /// Create a new group with a fresh random GMS at epoch 0.
    #[must_use]
    pub fn new() -> Self {
        let mut gms = [0_u8; 32];
        OsRng.fill_bytes(&mut gms);
        Self { gms, epoch: 0 }
    }

    /// Restore from an existing GMS at epoch 0. Only valid for initial group creation;
    /// post-ratchet restoration must use [`from_gms_and_epoch`](Self::from_gms_and_epoch).
    #[must_use]
    pub const fn from_gms(gms: [u8; 32]) -> Self {
        Self { gms, epoch: 0 }
    }

    /// Restore from an existing GMS and epoch (received via `unseal`).
    #[must_use]
    pub const fn from_gms_and_epoch(gms: [u8; 32], epoch: u32) -> Self {
        Self { gms, epoch }
    }

    /// Returns the raw 32-byte GMS. The name reflects intent: only the sealed-distribution
    /// path (`seal_for`) and sealed-at-rest persistence should ever need the raw bytes. Do
    /// not log the result, do not pass it across an untrusted channel.
    #[must_use]
    pub const fn dangerous_raw_gms(&self) -> &[u8; 32] {
        &self.gms
    }

    /// Returns the current epoch. Starts at 0 and increments by 1 on each `ratchet` call.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Forward-ratchets the GMS so removed members cannot derive future keys.
    ///
    /// The new GMS is `SHA256(PREFIX || rotation_salt || old_gms)`. The rotation salt must
    /// be a fresh 32-byte random value contributed by the member who initiates the rotation.
    /// Reusing a salt from a previous ratchet produces the same GMS as that previous
    /// ratchet, collapsing the key rotation. Callers must generate the salt from a secure random source.
    ///
    /// After ratcheting, all remaining controllers must receive the new `GroupKeyHolder`
    /// via `seal_for` / `unseal`.
    pub fn ratchet(&mut self, rotation_salt: [u8; 32]) {
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeyRatchet/GMS\x00\x00\x00";
        let mut hasher = sha2::Sha256::new();
        hasher.update(PREFIX);
        hasher.update(rotation_salt);
        hasher.update(self.gms);
        self.gms = hasher.finalize_fixed().into();
        self.epoch = self.epoch.checked_add(1).expect("epoch overflow");
    }

    /// Derive a per-PDA [`SecretSpendingKey`] by mixing the seed into the SHA-256 input.
    ///
    /// Each distinct `pda_seed` produces a distinct SSK in the full 256-bit space, so
    /// adversarial seed-grinding cannot collide two PDAs' derived keys under the same
    /// group. Uses the codebase's 32-byte protocol-versioned domain-separation convention.
    fn secret_spending_key_for_pda(&self, pda_seed: &PdaSeed) -> SecretSpendingKey {
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeyDerivation/SSK";
        let mut hasher = sha2::Sha256::new();
        hasher.update(PREFIX);
        hasher.update(self.gms);
        hasher.update(pda_seed.as_ref());
        SecretSpendingKey(hasher.finalize_fixed().into())
    }

    /// Derive keys for a specific PDA.
    ///
    /// All controllers holding the same GMS independently derive the same keys for the
    /// same PDA because the derivation is deterministic in (GMS, seed).
    #[must_use]
    pub fn derive_keys_for_pda(&self, pda_seed: &PdaSeed) -> PrivateKeyHolder {
        self.secret_spending_key_for_pda(pda_seed)
            .produce_private_key_holder(None)
    }

    /// Encrypts this holder's GMS and epoch under the recipient's [`ViewingPublicKey`].
    ///
    /// Uses an ephemeral ECDH key exchange to derive a shared secret, then AES-256-GCM
    /// to encrypt the payload. The returned bytes are
    /// `ephemeral_pubkey (33) || nonce (12) || ciphertext+tag (52)` = 97 bytes.
    ///
    /// Each call generates a fresh ephemeral key, so two seals of the same holder produce
    /// different ciphertexts.
    #[must_use]
    pub fn seal_for(&self, recipient_vpk: &ViewingPublicKey) -> Vec<u8> {
        let mut ephemeral_scalar: Scalar = [0_u8; 32];
        OsRng.fill_bytes(&mut ephemeral_scalar);
        let ephemeral_pubkey = ViewingPublicKey::from_scalar(ephemeral_scalar);
        let shared = SharedSecretKey::new(&ephemeral_scalar, recipient_vpk);
        let aes_key = Self::seal_kdf(&shared);
        let cipher = Aes256Gcm::new(&aes_key.into());

        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from(nonce_bytes);

        let mut plaintext = [0_u8; 36];
        plaintext[..32].copy_from_slice(&self.gms);
        plaintext[32..].copy_from_slice(&self.epoch.to_le_bytes());

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("AES-GCM encryption should not fail with valid key/nonce");

        let capacity = 33_usize
            .checked_add(12)
            .and_then(|n| n.checked_add(ciphertext.len()))
            .expect("seal capacity overflow");
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&ephemeral_pubkey.0);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypts a sealed `GroupKeyHolder` using the recipient's `ViewingSecretKey`.
    ///
    /// Returns `Err` if the ciphertext is too short, the ECDH point is invalid, or the
    /// AES-GCM authentication tag doesn't verify (wrong key or tampered data).
    pub fn unseal(sealed: &[u8], own_vsk: &ViewingSecretKey) -> Result<Self, SealError> {
        const HEADER_LEN: usize = 33 + 12;
        const MIN_LEN: usize = HEADER_LEN + 16;
        if sealed.len() < MIN_LEN {
            return Err(SealError::TooShort);
        }
        // MIN_LEN (61) > HEADER_LEN (45), so all slicing below is in bounds.
        let ephemeral_pubkey = Secp256k1Point(sealed[..33].to_vec());
        let nonce = aes_gcm::Nonce::from_slice(&sealed[33..HEADER_LEN]);
        let ciphertext = &sealed[HEADER_LEN..];

        let shared = SharedSecretKey::new(own_vsk, &ephemeral_pubkey);
        let aes_key = Self::seal_kdf(&shared);
        let cipher = Aes256Gcm::new(&aes_key.into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_err| SealError::DecryptionFailed)?;

        if plaintext.len() != 36 {
            return Err(SealError::DecryptionFailed);
        }

        let mut gms = [0_u8; 32];
        gms.copy_from_slice(&plaintext[..32]);
        let epoch = u32::from_le_bytes(plaintext[32..36].try_into().unwrap());
        Ok(Self::from_gms_and_epoch(gms, epoch))
    }

    /// Derives an AES-256 key from the ECDH shared secret via SHA-256 with a domain prefix.
    fn seal_kdf(shared: &SharedSecretKey) -> [u8; 32] {
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/GroupKeySeal/AES\x00\x00\x00\x00\x00\x00";
        let mut hasher = sha2::Sha256::new();
        hasher.update(PREFIX);
        hasher.update(shared.0);
        hasher.finalize_fixed().into()
    }
}

#[derive(Debug)]
pub enum SealError {
    TooShort,
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use nssa_core::NullifierPublicKey;

    use super::*;

    /// Two holders from the same GMS derive identical keys for the same PDA seed.
    #[test]
    fn same_gms_same_seed_produces_same_keys() {
        let gms = [42_u8; 32];
        let holder_a = GroupKeyHolder::from_gms(gms);
        let holder_b = GroupKeyHolder::from_gms(gms);
        let seed = PdaSeed::new([1; 32]);

        let keys_a = holder_a.derive_keys_for_pda(&seed);
        let keys_b = holder_b.derive_keys_for_pda(&seed);

        assert_eq!(
            keys_a.generate_nullifier_public_key().to_byte_array(),
            keys_b.generate_nullifier_public_key().to_byte_array(),
        );
    }

    /// Different PDA seeds produce different keys from the same GMS.
    #[test]
    fn same_gms_different_seed_produces_different_keys() {
        let holder = GroupKeyHolder::from_gms([42_u8; 32]);
        let seed_a = PdaSeed::new([1; 32]);
        let seed_b = PdaSeed::new([2; 32]);

        let npk_a = holder
            .derive_keys_for_pda(&seed_a)
            .generate_nullifier_public_key();
        let npk_b = holder
            .derive_keys_for_pda(&seed_b)
            .generate_nullifier_public_key();

        assert_ne!(npk_a.to_byte_array(), npk_b.to_byte_array());
    }

    /// Different GMS produce different keys for the same PDA seed.
    #[test]
    fn different_gms_same_seed_produces_different_keys() {
        let holder_a = GroupKeyHolder::from_gms([42_u8; 32]);
        let holder_b = GroupKeyHolder::from_gms([99_u8; 32]);
        let seed = PdaSeed::new([1; 32]);

        let npk_a = holder_a
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        let npk_b = holder_b
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        assert_ne!(npk_a.to_byte_array(), npk_b.to_byte_array());
    }

    /// GMS round-trip: export and restore produces the same keys.
    #[test]
    fn gms_round_trip() {
        let original = GroupKeyHolder::from_gms([7_u8; 32]);
        let restored = GroupKeyHolder::from_gms(*original.dangerous_raw_gms());
        let seed = PdaSeed::new([1; 32]);

        let npk_original = original
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        let npk_restored = restored
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        assert_eq!(npk_original.to_byte_array(), npk_restored.to_byte_array());
    }

    /// The derived `NullifierPublicKey` is non-zero (sanity check).
    #[test]
    fn derived_npk_is_non_zero() {
        let holder = GroupKeyHolder::from_gms([42_u8; 32]);
        let seed = PdaSeed::new([1; 32]);
        let npk = holder
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        assert_ne!(npk, NullifierPublicKey([0; 32]));
    }

    /// Pins the end-to-end derivation for a fixed (GMS, `ProgramId`, `PdaSeed`). Any change
    /// to `secret_spending_key_for_pda`, the `PrivateKeyHolder` nsk/npk chain, or the
    /// `AccountId::for_private_pda` formula breaks this test. Mirrors the pinned-value
    /// pattern from `for_private_pda_matches_pinned_value` in `nssa_core`.
    #[test]
    fn pinned_end_to_end_derivation_for_private_pda() {
        use nssa_core::{account::AccountId, program::ProgramId};

        let gms = [42_u8; 32];
        let seed = PdaSeed::new([1; 32]);
        let program_id: ProgramId = [9; 8];

        let holder = GroupKeyHolder::from_gms(gms);
        let npk = holder
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        let account_id = AccountId::for_private_pda(&program_id, &seed, &npk);

        let expected_npk = NullifierPublicKey([
            185, 161, 225, 224, 20, 156, 173, 0, 6, 173, 74, 136, 16, 88, 71, 154, 101, 160, 224,
            162, 247, 98, 183, 210, 118, 130, 143, 237, 20, 112, 111, 114,
        ]);
        let expected_account_id = AccountId::new([
            236, 138, 175, 184, 194, 233, 144, 109, 157, 51, 193, 120, 83, 110, 147, 90, 154, 57,
            148, 236, 12, 92, 135, 38, 253, 79, 88, 143, 161, 175, 46, 144,
        ]);

        assert_eq!(npk, expected_npk);
        assert_eq!(account_id, expected_account_id);
    }

    /// Wallets persist `GroupKeyHolder` to disk and reload it on startup. This test pins
    /// the serde round-trip: serialize, deserialize, and assert the derived keys for a
    /// sample seed match on both sides. A silent encoding drift would corrupt every
    /// group-owned account.
    #[test]
    fn gms_serde_round_trip_preserves_derivation() {
        let mut original = GroupKeyHolder::from_gms([7_u8; 32]);
        original.ratchet([10_u8; 32]);
        let encoded = bincode::serialize(&original).expect("serialize");
        let restored: GroupKeyHolder = bincode::deserialize(&encoded).expect("deserialize");

        let seed = PdaSeed::new([1; 32]);
        let npk_original = original
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        let npk_restored = restored
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        assert_eq!(npk_original, npk_restored);
        assert_eq!(original.dangerous_raw_gms(), restored.dangerous_raw_gms());
        assert_eq!(original.epoch(), restored.epoch());
    }

    /// A `GroupKeyHolder` constructed from the same 32 bytes as a personal
    /// `SecretSpendingKey` must not derive the same `NullifierPublicKey` as the personal
    /// path, so a private PDA cannot be spent by a personal nullifier even under
    /// adversarial key-material reuse. The safety rests on the group path's distinct
    /// domain-separation prefix plus the seed mix-in (see `secret_spending_key_for_pda`).
    #[test]
    fn group_derivation_does_not_collide_with_personal_path_at_shared_bytes() {
        let shared_bytes = [13_u8; 32];
        let seed = PdaSeed::new([5; 32]);

        let group_npk = GroupKeyHolder::from_gms(shared_bytes)
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        let personal_npk = SecretSpendingKey(shared_bytes)
            .produce_private_key_holder(None)
            .generate_nullifier_public_key();

        assert_ne!(group_npk, personal_npk);
    }

    /// Ratcheting advances the epoch by 1.
    #[test]
    fn ratchet_advances_epoch() {
        let mut holder = GroupKeyHolder::from_gms([42_u8; 32]);
        assert_eq!(holder.epoch(), 0);
        holder.ratchet([1_u8; 32]);
        assert_eq!(holder.epoch(), 1);
        holder.ratchet([2_u8; 32]);
        assert_eq!(holder.epoch(), 2);
    }

    /// After ratcheting, the same PDA seed produces a different npk. A removed member
    /// holding the old GMS cannot derive the new keys.
    #[test]
    fn ratchet_changes_derived_keys() {
        let mut holder = GroupKeyHolder::from_gms([42_u8; 32]);
        let seed = PdaSeed::new([1; 32]);
        let npk_before = holder
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        holder.ratchet([99_u8; 32]);
        let npk_after = holder
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        assert_ne!(npk_before, npk_after);
    }

    /// Two holders ratcheted with different salts diverge, even from the same starting GMS.
    #[test]
    fn different_salts_produce_different_ratcheted_keys() {
        let mut holder_a = GroupKeyHolder::from_gms([42_u8; 32]);
        let mut holder_b = GroupKeyHolder::from_gms([42_u8; 32]);
        holder_a.ratchet([1_u8; 32]);
        holder_b.ratchet([2_u8; 32]);
        let seed = PdaSeed::new([1; 32]);
        let npk_a = holder_a
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        let npk_b = holder_b
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();
        assert_ne!(npk_a, npk_b);
    }

    /// `from_gms_and_epoch` restores a holder at a specific epoch, matching the state
    /// after that many ratchets.
    #[test]
    fn from_gms_and_epoch_restores_correctly() {
        let mut holder = GroupKeyHolder::from_gms([42_u8; 32]);
        holder.ratchet([1_u8; 32]);
        let restored =
            GroupKeyHolder::from_gms_and_epoch(*holder.dangerous_raw_gms(), holder.epoch());
        assert_eq!(restored.epoch(), 1);
        let seed = PdaSeed::new([1; 32]);
        assert_eq!(
            holder
                .derive_keys_for_pda(&seed)
                .generate_nullifier_public_key(),
            restored
                .derive_keys_for_pda(&seed)
                .generate_nullifier_public_key(),
        );
    }

    /// A removed member holding the pre-ratchet GMS cannot derive the post-ratchet
    /// keys, even if they know the PDA seed. This is the forward-secrecy property of
    /// the ratchet: the old GMS is a preimage of the new one under SHA-256, so
    /// reversing the ratchet requires breaking preimage resistance.
    #[test]
    fn removed_member_cannot_derive_post_ratchet_keys() {
        let original_gms = [42_u8; 32];
        let seed = PdaSeed::new([1; 32]);

        // Removed member's frozen state
        let removed = GroupKeyHolder::from_gms(original_gms);
        let removed_npk = removed
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        // Remaining members ratchet twice
        let mut active = GroupKeyHolder::from_gms(original_gms);
        active.ratchet([10_u8; 32]);
        active.ratchet([20_u8; 32]);
        let active_npk = active
            .derive_keys_for_pda(&seed)
            .generate_nullifier_public_key();

        // The removed member's keys are useless for the current epoch
        assert_ne!(removed_npk, active_npk);
        assert_ne!(removed.dangerous_raw_gms(), active.dangerous_raw_gms());
        assert_eq!(removed.epoch(), 0);
        assert_eq!(active.epoch(), 2);
    }

    /// Seal then unseal recovers the same GMS, epoch, and derived keys.
    #[test]
    fn seal_unseal_round_trip() {
        let mut holder = GroupKeyHolder::from_gms([42_u8; 32]);
        holder.ratchet([10_u8; 32]);

        let recipient_ssk = SecretSpendingKey([7_u8; 32]);
        let recipient_keys = recipient_ssk.produce_private_key_holder(None);
        let recipient_vpk = recipient_keys.generate_viewing_public_key();
        let recipient_vsk = recipient_keys.viewing_secret_key;

        let sealed = holder.seal_for(&recipient_vpk);
        let restored = GroupKeyHolder::unseal(&sealed, &recipient_vsk).expect("unseal");

        assert_eq!(restored.dangerous_raw_gms(), holder.dangerous_raw_gms());
        assert_eq!(restored.epoch(), holder.epoch());

        let seed = PdaSeed::new([1; 32]);
        assert_eq!(
            holder
                .derive_keys_for_pda(&seed)
                .generate_nullifier_public_key(),
            restored
                .derive_keys_for_pda(&seed)
                .generate_nullifier_public_key(),
        );
    }

    /// Unsealing with a different VSK fails with `DecryptionFailed`.
    #[test]
    fn unseal_wrong_vsk_fails() {
        let holder = GroupKeyHolder::from_gms([42_u8; 32]);

        let recipient_ssk = SecretSpendingKey([7_u8; 32]);
        let recipient_vpk = recipient_ssk
            .produce_private_key_holder(None)
            .generate_viewing_public_key();

        let wrong_ssk = SecretSpendingKey([99_u8; 32]);
        let wrong_vsk = wrong_ssk
            .produce_private_key_holder(None)
            .viewing_secret_key;

        let sealed = holder.seal_for(&recipient_vpk);
        let result = GroupKeyHolder::unseal(&sealed, &wrong_vsk);
        assert!(matches!(result, Err(super::SealError::DecryptionFailed)));
    }

    /// Tampered ciphertext fails authentication.
    #[test]
    fn unseal_tampered_ciphertext_fails() {
        let holder = GroupKeyHolder::from_gms([42_u8; 32]);

        let recipient_ssk = SecretSpendingKey([7_u8; 32]);
        let recipient_keys = recipient_ssk.produce_private_key_holder(None);
        let recipient_vpk = recipient_keys.generate_viewing_public_key();
        let recipient_vsk = recipient_keys.viewing_secret_key;

        let mut sealed = holder.seal_for(&recipient_vpk);
        // Flip a byte in the ciphertext portion (after ephemeral_pubkey + nonce)
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        let result = GroupKeyHolder::unseal(&sealed, &recipient_vsk);
        assert!(matches!(result, Err(super::SealError::DecryptionFailed)));
    }

    /// Two seals of the same holder produce different ciphertexts (ephemeral randomness).
    #[test]
    fn two_seals_produce_different_ciphertexts() {
        let holder = GroupKeyHolder::from_gms([42_u8; 32]);

        let recipient_ssk = SecretSpendingKey([7_u8; 32]);
        let recipient_vpk = recipient_ssk
            .produce_private_key_holder(None)
            .generate_viewing_public_key();

        let sealed_a = holder.seal_for(&recipient_vpk);
        let sealed_b = holder.seal_for(&recipient_vpk);
        assert_ne!(sealed_a, sealed_b);
    }

    /// Sealed payload is too short.
    #[test]
    fn unseal_too_short_fails() {
        let vsk: ViewingSecretKey = [7_u8; 32];
        let result = GroupKeyHolder::unseal(&[0_u8; 10], &vsk);
        assert!(matches!(result, Err(super::SealError::TooShort)));
    }

    /// Degenerate GMS values (all-zeros, all-ones, single-bit) must still produce valid,
    /// non-zero, pairwise-distinct npks. Rules out accidental "if gms == default { return
    /// default }" style shortcuts in the derivation.
    #[test]
    fn degenerate_gms_produces_distinct_non_zero_keys() {
        let seed = PdaSeed::new([1; 32]);
        let degenerate = [[0_u8; 32], [0xFF_u8; 32], {
            let mut v = [0_u8; 32];
            v[0] = 1;
            v
        }];

        let npks: Vec<NullifierPublicKey> = degenerate
            .iter()
            .map(|gms| {
                GroupKeyHolder::from_gms(*gms)
                    .derive_keys_for_pda(&seed)
                    .generate_nullifier_public_key()
            })
            .collect();

        for npk in &npks {
            assert_ne!(*npk, NullifierPublicKey([0; 32]));
        }
        for (i, a) in npks.iter().enumerate() {
            for b in &npks[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// Full lifecycle: create group, distribute GMS via seal/unseal, verify key
    /// agreement, ratchet for forward secrecy.
    #[test]
    fn group_pda_lifecycle() {
        use nssa_core::account::AccountId;

        let alice_holder = GroupKeyHolder::new();
        assert_eq!(alice_holder.epoch(), 0);
        let pda_seed = PdaSeed::new([42_u8; 32]);
        let program_id: nssa_core::program::ProgramId = [1; 8];

        // Derive Alice's keys
        let alice_keys = alice_holder.derive_keys_for_pda(&pda_seed);
        let alice_npk = alice_keys.generate_nullifier_public_key();

        // Seal GMS for Bob using Bob's viewing key, Bob unseals
        let bob_ssk = SecretSpendingKey([77_u8; 32]);
        let bob_keys = bob_ssk.produce_private_key_holder(None);
        let bob_vpk = bob_keys.generate_viewing_public_key();
        let bob_vsk = bob_keys.viewing_secret_key;

        let sealed = alice_holder.seal_for(&bob_vpk);
        let bob_holder =
            GroupKeyHolder::unseal(&sealed, &bob_vsk).expect("Bob should unseal the GMS");

        // Key agreement: both derive identical NPK and AccountId
        let bob_npk = bob_holder
            .derive_keys_for_pda(&pda_seed)
            .generate_nullifier_public_key();
        assert_eq!(alice_npk, bob_npk);

        let alice_account_id = AccountId::for_private_pda(&program_id, &pda_seed, &alice_npk);
        let bob_account_id = AccountId::for_private_pda(&program_id, &pda_seed, &bob_npk);
        assert_eq!(alice_account_id, bob_account_id);

        // Ratchet: forward secrecy
        let mut ratcheted_holder = alice_holder;
        ratcheted_holder.ratchet([99_u8; 32]);
        assert_eq!(ratcheted_holder.epoch(), 1);

        let ratcheted_npk = ratcheted_holder
            .derive_keys_for_pda(&pda_seed)
            .generate_nullifier_public_key();
        let bob_stale_npk = bob_holder
            .derive_keys_for_pda(&pda_seed)
            .generate_nullifier_public_key();

        assert_ne!(ratcheted_npk, bob_stale_npk);
        assert_ne!(ratcheted_npk, alice_npk);

        let new_account_id = AccountId::for_private_pda(&program_id, &pda_seed, &ratcheted_npk);
        assert_ne!(alice_account_id, new_account_id);

        // Bob's stale keys point to old address
        let bob_stale_id = AccountId::for_private_pda(&program_id, &pda_seed, &bob_stale_npk);
        assert_eq!(bob_stale_id, alice_account_id);
        assert_ne!(bob_stale_id, new_account_id);

        // Sealed round-trip of ratcheted GMS
        let sealed_ratcheted = ratcheted_holder.seal_for(&bob_vpk);
        let restored = GroupKeyHolder::unseal(&sealed_ratcheted, &bob_vsk)
            .expect("Should unseal ratcheted GMS");
        assert_eq!(
            restored.dangerous_raw_gms(),
            ratcheted_holder.dangerous_raw_gms()
        );
        assert_eq!(restored.epoch(), 1);
    }
}
