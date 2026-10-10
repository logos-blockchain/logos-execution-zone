use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{
    Commitment, EncryptedNote, Recipient, RecipientEncryption,
    encryption::{Ciphertext, SharedSecretKey, apply_keystream, pad_to_floor},
    program::MessageBody,
};
#[cfg(feature = "host")]
use crate::{NullifierPublicKey, PrivateAccountKind, encryption::ViewingPublicKey};

const KEY_DOMAIN: &[u8; 28] = b"LEE/v0.3/KDF-SHA256/Message/";

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct SealedCast {
    pub commitment: Commitment,
    pub note: EncryptedNote,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidCastSeal {
    #[error("Each durable Cast of private execution needs exactly one seal")]
    Unpaired,
    #[error("A seal must address its Cast's destination")]
    MisaddressedSeal,
}

impl RecipientEncryption {
    #[must_use]
    pub fn seal_message(&self, body: &MessageBody, pad_to_len: Option<u32>) -> Option<SealedCast> {
        let Recipient {
            vpk, kind, opening, ..
        } = &self.recipient;
        if body.to.account_id != self.recipient.address() {
            return None;
        }
        let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &self.esk);
        let commitment = Commitment::for_sealed_message(body, &hiding_randomness(&shared_secret));
        // A fixed-width header, so neither the destination's kind nor its alias shows in the
        // length.
        let mut plaintext = kind.to_header_bytes().to_vec();
        plaintext.push(u8::from(opening.is_some()));
        plaintext.extend_from_slice(&opening.unwrap_or_default());
        plaintext
            .extend_from_slice(&borsh::to_vec(body).expect("borsh serialization is infallible"));
        pad_to_floor(&mut plaintext, pad_to_len);
        apply_keystream(
            &mut plaintext,
            KEY_DOMAIN,
            &shared_secret,
            &commitment.to_byte_array(),
        );
        Some(SealedCast {
            commitment,
            note: EncryptedNote {
                epk,
                ciphertext: Ciphertext(plaintext),
            },
        })
    }
}

#[cfg(feature = "host")]
impl SealedCast {
    #[must_use]
    pub fn open(
        &self,
        npk: NullifierPublicKey,
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Option<(MessageBody, Recipient, [u8; 32])> {
        let shared_secret = SharedSecretKey::decapsulate(&self.note.epk, d, z)?;
        let mut plaintext = self.note.ciphertext.0.clone();
        apply_keystream(
            &mut plaintext,
            KEY_DOMAIN,
            &shared_secret,
            &self.commitment.to_byte_array(),
        );
        let (header, after_header) =
            plaintext.split_first_chunk::<{ PrivateAccountKind::HEADER_LEN }>()?;
        let (&[present], after_flag) = after_header.split_first_chunk::<1>()?;
        let (opening_bytes, mut encoded) = after_flag.split_first_chunk::<32>()?;
        let kind = PrivateAccountKind::from_header_bytes(header)?;
        let opening = match present {
            0 => None,
            1 => Some(*opening_bytes),
            _ => return None,
        };
        let body: MessageBody = BorshDeserialize::deserialize(&mut encoded).ok()?;
        let rho = hiding_randomness(&shared_secret);
        let recipient = Recipient {
            npk,
            vpk: ViewingPublicKey::from_seed(d, z),
            kind,
            opening,
        };
        (Commitment::for_sealed_message(&body, &rho) == self.commitment
            && recipient.address() == body.to.account_id)
            .then_some((body, recipient, rho))
    }
}

/// # Errors
/// Returns an error unless `seals` pairs every Cast with a seal addressing it.
pub fn seal_casts(
    casts: &[MessageBody],
    seals: Vec<RecipientEncryption>,
    pad_to_len: Option<u32>,
) -> Result<Vec<SealedCast>, InvalidCastSeal> {
    if casts.len() != seals.len() {
        return Err(InvalidCastSeal::Unpaired);
    }
    casts
        .iter()
        .zip(seals)
        .map(|(body, seal)| {
            seal.seal_message(body, pad_to_len)
                .ok_or(InvalidCastSeal::MisaddressedSeal)
        })
        .collect()
}

fn hiding_randomness(shared_secret: &SharedSecretKey) -> [u8; 32] {
    const PREFIX: &[u8; 24] = b"LEE/v0.3/KDF-SHA256/Rho/";
    let mut bytes = [0_u8; 24 + 32];
    bytes[..24].copy_from_slice(PREFIX);
    bytes[24..].copy_from_slice(&shared_secret.0);
    Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

#[cfg(feature = "host")]
