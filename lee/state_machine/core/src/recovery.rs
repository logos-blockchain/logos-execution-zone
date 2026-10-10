use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    NullifierPublicKey,
    account::AccountId,
    encryption::{
        Ciphertext, EncryptedNote, EphemeralSecretKey, SharedSecretKey, ViewingPublicKey,
        apply_keystream,
    },
    program::PrivateAccountKind,
};

const PLAINTEXT_LEN: usize = 32 + PrivateAccountKind::HEADER_LEN + 1 + 32;
const KEY_DOMAIN: &[u8; 29] = b"LEE/v0.3/KDF-SHA256/Recovery/";

/// Private recipient of a message.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct Recipient {
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
    pub kind: PrivateAccountKind,
    /// Blinding factor.
    pub opening: Option<[u8; 32]>,
}

/// Material to produce an encryption ciphertext.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct RecipientEncryption {
    pub recipient: Recipient,
    /// The ephemeral key for ciphertext production.
    pub esk: EphemeralSecretKey,
}

/// Binding allowing to recover a blinded address for the appropriate key owner.
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct RecoveryBinding {
    pub address: AccountId,
    pub note: EncryptedNote,
}

impl Recipient {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::for_private_account(&self.npk, &self.vpk, &self.kind)
    }

    #[must_use]
    pub fn address(&self) -> AccountId {
        let account_id = self.account_id();
        self.opening
            .map_or(account_id, |opening| account_id.blinded(&opening))
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub fn recover(
        address: AccountId,
        note: &EncryptedNote,
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Option<Self> {
        let shared_secret = SharedSecretKey::decapsulate(&note.epk, d, z)?;
        let mut plaintext = note.ciphertext.0.clone();
        apply_keystream(&mut plaintext, KEY_DOMAIN, &shared_secret, address.value());
        let (npk, kind, opening) = BorshDeserialize::deserialize(&mut plaintext.as_slice()).ok()?;
        let recipient = Self {
            npk,
            vpk: ViewingPublicKey::from_seed(d, z),
            kind,
            opening,
        };
        (recipient.address() == address).then_some(recipient)
    }
}

impl RecipientEncryption {
    #[must_use]
    pub fn bind_recovery(&self) -> RecoveryBinding {
        let Recipient {
            npk,
            vpk,
            kind,
            opening,
        } = &self.recipient;
        let address = self.recipient.address();
        let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &self.esk);
        let mut plaintext =
            borsh::to_vec(&(npk, kind, opening)).expect("borsh serialization is infallible");
        plaintext.resize(PLAINTEXT_LEN, 0);
        apply_keystream(&mut plaintext, KEY_DOMAIN, &shared_secret, address.value());
        RecoveryBinding {
            address,
            note: EncryptedNote {
                epk,
                ciphertext: Ciphertext(plaintext),
            },
        }
    }
}

#[cfg(feature = "host")]
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{encryption::note_key, program::PdaSeed};

    const D: [u8; 32] = [1; 32];
    const Z: [u8; 32] = [2; 32];
    const NPK: NullifierPublicKey = NullifierPublicKey([3; 32]);

    fn recipient(kind: PrivateAccountKind, opening: Option<[u8; 32]>) -> Recipient {
        Recipient {
            npk: NPK,
            vpk: ViewingPublicKey::from_seed(&D, &Z),
            kind,
            opening,
        }
    }

    fn kinds() -> [PrivateAccountKind; 2] {
        [
            PrivateAccountKind::Regular,
            PrivateAccountKind::Pda {
                account_id: AccountId::new([5; 32]),
                seed: PdaSeed::new([6; 32]),
            },
        ]
    }

    fn bind(recipient: Recipient) -> RecoveryBinding {
        RecipientEncryption {
            recipient,
            esk: EphemeralSecretKey([8; 32]),
        }
        .bind_recovery()
    }

    #[test]
    fn a_binding_names_its_recipients_account_or_the_alias_its_opening_selects() {
        for kind in kinds() {
            let account_id =
                AccountId::for_private_account(&NPK, &ViewingPublicKey::from_seed(&D, &Z), &kind);

            assert_eq!(bind(recipient(kind.clone(), None)).address, account_id);
            assert_eq!(
                bind(recipient(kind, Some([9; 32]))).address,
                account_id.blinded(&[9; 32])
            );
        }
    }

    #[test]
    fn a_recovery_note_opens_to_its_recipient_only_under_its_viewing_secret_and_address() {
        for kind in kinds() {
            for opening in [None, Some([9; 32])] {
                let expected = recipient(kind.clone(), opening);
                let RecoveryBinding { address, note } = bind(expected.clone());

                assert_eq!(Recipient::recover(address, &note, &D, &Z), Some(expected));
                assert_eq!(
                    Recipient::recover(address, &note, &[10; 32], &[11; 32]),
                    None
                );
                assert_eq!(
                    Recipient::recover(AccountId::new([12; 32]), &note, &D, &Z),
                    None
                );
            }
        }
    }

    #[test]
    fn every_recovery_note_has_one_length() {
        let lengths: BTreeSet<usize> = kinds()
            .into_iter()
            .flat_map(|kind| {
                [None, Some([9; 32])].map(|opening| {
                    bind(recipient(kind.clone(), opening))
                        .note
                        .ciphertext
                        .0
                        .len()
                })
            })
            .collect();

        assert_eq!(lengths, BTreeSet::from([PLAINTEXT_LEN]));
    }

    #[test]
    fn the_recovery_key_matches_its_pinned_derivation() {
        assert_eq!(
            note_key(
                KEY_DOMAIN,
                &SharedSecretKey([1; 32]),
                AccountId::new([2; 32]).value()
            ),
            [
                123, 198, 241, 111, 152, 68, 119, 130, 150, 194, 252, 251, 51, 227, 67, 212, 237,
                28, 208, 233, 118, 90, 57, 206, 144, 119, 185, 61, 129, 76, 221, 222,
            ]
        );
    }
}
