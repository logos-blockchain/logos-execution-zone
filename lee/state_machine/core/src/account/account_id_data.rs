use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    Identifier, NullifierPublicKey, account::AccountId, encryption::ViewingPublicKey,
    program::PdaSeed,
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountIdData {
    shielded_data: Option<ShieldedData>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct ShieldedData {
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
}

impl AccountIdData {
    #[must_use]
    pub const fn public() -> Self {
        Self {
            shielded_data: None,
        }
    }

    #[must_use]
    pub fn derive_pda_id(&self, program_id: AccountId, seed: &PdaSeed) -> AccountId {
        self.shielded_data.as_ref().map_or_else(
            || AccountId::for_public_pda(&program_id, seed),
            |data| {
                AccountId::for_private_pda(&program_id, seed, &data.npk, &data.vpk, data.identifier)
            },
        )
    }

    #[cfg(any(feature = "host", test))]
    #[must_use]
    pub const fn from_private_parts(
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        Self {
            shielded_data: Some(ShieldedData {
                npk,
                vpk,
                identifier,
            }),
        }
    }

    #[cfg(any(feature = "host", test))]
    #[must_use]
    pub const fn private_parts(
        &self,
    ) -> Option<(&NullifierPublicKey, &ViewingPublicKey, Identifier)> {
        match &self.shielded_data {
            None => None,
            Some(data) => Some((&data.npk, &data.vpk, data.identifier)),
        }
    }
}
