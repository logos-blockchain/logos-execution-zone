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
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chacha20::{
        ChaCha20,
        cipher::{KeyIvInit as _, StreamCipher as _},
    };

    use super::*;
    use crate::{
        account::{AccountId, Actor},
        encryption::EphemeralSecretKey,
        program::PdaSeed,
    };

    const D: [u8; 32] = [0; 32];
    const Z: [u8; 32] = [1; 32];
    const NPK: NullifierPublicKey = NullifierPublicKey([2; 32]);
    const ESK: EphemeralSecretKey = EphemeralSecretKey([3; 32]);

    // A regular and a PDA recipient, each at its canonical address and at an alias.
    fn recipients() -> [Recipient; 4] {
        let regular = PrivateAccountKind::Regular;
        let pda = PrivateAccountKind::Pda {
            account_id: AccountId::new([5; 32]),
            seed: PdaSeed::new([6; 32]),
        };
        [
            (regular.clone(), None),
            (regular, Some([7; 32])),
            (pda.clone(), None),
            (pda, Some([7; 32])),
        ]
        .map(|(kind, opening)| Recipient {
            npk: NPK,
            vpk: ViewingPublicKey::from_seed(&D, &Z),
            kind,
            opening,
        })
    }

    fn body(to: AccountId) -> MessageBody {
        MessageBody {
            from: Actor::new(AccountId::new([8; 32]), AccountId::new([9; 32])),
            to: Actor::new(to, AccountId::new([10; 32])),
            message: vec![11; 2],
        }
    }

    fn sealed(recipient: &Recipient) -> SealedCast {
        RecipientEncryption {
            recipient: recipient.clone(),
            esk: ESK,
        }
        .seal_message(&body(recipient.address()), Some(512))
        .unwrap()
    }

    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        Impl::hash_bytes(&parts.concat())
            .as_bytes()
            .try_into()
            .unwrap()
    }

    #[test]
    fn a_sealed_cast_commits_to_its_envelope_and_encrypts_it_as_documented() {
        for recipient in recipients() {
            let sealed = sealed(&recipient);
            let body = body(recipient.address());
            let (shared_secret, epk) =
                SharedSecretKey::encapsulate_deterministic(&recipient.vpk, &ESK);
            let rho = hash(&[b"LEE/v0.3/KDF-SHA256/Rho/".as_slice(), &shared_secret.0]);
            let commitment = hash(&[
                b"/LEE/v0.3/Commitment/Sealed/\x00\x00\x00\x00".as_slice(),
                &hash(&[&borsh::to_vec(&body).unwrap()]),
                &rho,
            ]);
            let key = hash(&[
                b"LEE/v0.3/KDF-SHA256/Message/".as_slice(),
                &shared_secret.0,
                &commitment,
            ]);
            let mut plaintext = sealed.note.ciphertext.0.clone();
            ChaCha20::new(&key.into(), &[0; 12].into()).apply_keystream(&mut plaintext);
            let mut expected = recipient.kind.to_header_bytes().to_vec();
            expected.push(u8::from(recipient.opening.is_some()));
            expected.extend_from_slice(&recipient.opening.unwrap_or_default());
            expected.extend_from_slice(&borsh::to_vec(&body).unwrap());
            expected.resize(512, 0);

            assert_eq!(sealed.note.epk, epk);
            assert_eq!(sealed.commitment.to_byte_array(), commitment);
            assert_eq!(plaintext, expected);
        }
    }

    #[test]
    fn a_sealed_cast_opens_only_to_its_recipient_and_only_as_committed() {
        for recipient in recipients() {
            let sealed = sealed(&recipient);
            let (body, opened, _) = sealed.open(NPK, &D, &Z).unwrap();
            assert_eq!(
                (body.to.account_id, opened),
                (recipient.address(), recipient)
            );
            let mut altered = sealed.clone();
            // The sender's first byte, past the header, the flag and the opening.
            altered.note.ciphertext.0[PrivateAccountKind::HEADER_LEN + 1 + 32] ^= 1;
            let misplaced = SealedCast {
                commitment: Commitment::from_byte_array([12; 32]),
                ..sealed.clone()
            };

            // ML-KEM derives the key pair from `d` alone; `z` only seeds implicit rejection.
            for (case, refused) in [
                ("another viewing key", sealed.open(NPK, &[12; 32], &Z)),
                (
                    "another nullifier key",
                    sealed.open(NullifierPublicKey([12; 32]), &D, &Z),
                ),
                ("an altered body", altered.open(NPK, &D, &Z)),
                ("another commitment", misplaced.open(NPK, &D, &Z)),
            ] {
                assert!(refused.is_none(), "{case}");
            }
        }
    }

    #[test]
    fn every_sealed_note_under_its_floor_has_one_length() {
        let lengths: BTreeSet<_> = recipients()
            .iter()
            .map(|recipient| sealed(recipient).note.ciphertext.0.len())
            .collect();

        assert_eq!(lengths, BTreeSet::from([512]));
    }

    #[test]
    fn a_seal_refuses_a_body_addressed_anywhere_but_its_recipient() {
        for recipient in recipients() {
            let seal = RecipientEncryption {
                recipient: recipient.clone(),
                esk: ESK,
            };
            // The canonical address when the recipient takes an alias, and the alias otherwise.
            let other_form = if recipient.opening.is_some() {
                recipient.account_id()
            } else {
                recipient.account_id().blinded(&[7; 32])
            };

            for to in [AccountId::new([12; 32]), other_form] {
                assert!(seal.seal_message(&body(to), None).is_none());
            }
        }
    }

    #[test]
    fn each_cast_is_sealed_by_the_seal_paired_with_it() {
        let [recipient, ..] = recipients();
        let to_recipient = body(recipient.address());
        let seal = || RecipientEncryption {
            recipient: recipient.clone(),
            esk: ESK,
        };

        let sealed = seal_casts(std::slice::from_ref(&to_recipient), vec![seal()], None).unwrap();
        assert_eq!(
            sealed
                .iter()
                .map(|cast| cast.open(NPK, &D, &Z).map(|(body, ..)| body))
                .collect::<Vec<_>>(),
            vec![Some(to_recipient.clone())]
        );

        for (case, casts, seals, refusal) in [
            (
                "a missing seal",
                vec![to_recipient],
                vec![],
                InvalidCastSeal::Unpaired,
            ),
            (
                "a surplus seal",
                vec![],
                vec![seal()],
                InvalidCastSeal::Unpaired,
            ),
            (
                "a seal to another destination",
                vec![body(AccountId::new([12; 32]))],
                vec![seal()],
                InvalidCastSeal::MisaddressedSeal,
            ),
        ] {
            assert_eq!(
                seal_casts(&casts, seals, None).unwrap_err().to_string(),
                refusal.to_string(),
                "{case}"
            );
        }
    }
}
