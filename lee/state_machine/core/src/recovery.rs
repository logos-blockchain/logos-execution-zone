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

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct Recipient {
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
    pub kind: PrivateAccountKind,
    pub opening: Option<[u8; 32]>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct RecipientEncryption {
    pub recipient: Recipient,
    pub esk: EphemeralSecretKey,
}

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
